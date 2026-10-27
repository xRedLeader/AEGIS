#!/usr/bin/env python3
"""Operator-installed, durable, idempotent Unix notification receiver.

The receiver is a separate *non-root* OS service, with no access to AEGIS
assessment ledgers, reports, target code, or signing keys. It persists only
bounded canonical notification metadata and acknowledges after SQLite commit.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import socket
import sqlite3
import stat
import struct
import sys
import threading

from aegis_reporting import canonical, ID
from aegis_supervisor import ExecutionDenied, deny, open_directory_nofollow, private_directory

HEX = re.compile(r"[0-9a-f]{64}\Z")
CHALLENGE = re.compile(r"[0-9a-f]{32}\Z")
ENGAGEMENT = re.compile(r"[a-z][a-z0-9-]{7,63}\Z")
REQUIRED = frozenset({"type", "notice_id", "engagement_id", "source_run_id", "report_sha256",
                      "lead_count", "assessment_status", "challenge"})
MAX_MESSAGE = 2048


def _validated_policy(file: Path):
    path = Path(file)
    if not path.is_absolute():
        deny("receiver policy path must be absolute")
    with open_directory_nofollow(path.parent) as directory:
        st = os.fstat(directory)
        if st.st_uid not in (0, os.geteuid()) or st.st_mode & 0o022:
            deny("receiver policy directory is untrusted")
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=directory)
        try:
            st = os.fstat(fd)
            if (not stat.S_ISREG(st.st_mode) or st.st_uid not in (0, os.geteuid()) or
                    st.st_mode & 0o077 or st.st_size > 8192):
                deny("receiver policy must be protected")
            raw = os.read(fd, 8193)
        finally:
            os.close(fd)
    try:
        policy = json.loads(raw)
    except (ValueError, UnicodeError) as exc:
        raise ExecutionDenied("invalid receiver policy") from exc
    expected = {"schema_version", "configured", "socket_path", "state_root", "shared_gid",
                "allowed_sender_uids", "allowed_engagement_ids"}
    if (not isinstance(policy, dict) or set(policy) != expected or
            policy["schema_version"] != 1 or policy["configured"] is not True or
            not isinstance(policy["allowed_sender_uids"], list) or
            not 1 <= len(policy["allowed_sender_uids"]) <= 16 or
            any(type(uid) is not int or uid < 0 for uid in policy["allowed_sender_uids"]) or
            not isinstance(policy["allowed_engagement_ids"], list) or
            not 1 <= len(policy["allowed_engagement_ids"]) <= 32 or
            any(not isinstance(e, str) or not ENGAGEMENT.fullmatch(e)
                for e in policy["allowed_engagement_ids"]) or
            (policy["shared_gid"] is not None and
             (type(policy["shared_gid"]) is not int or policy["shared_gid"] < 0))):
        deny("invalid positively configured receiver policy")
    for key in ("socket_path", "state_root"):
        value = policy[key]
        if (not isinstance(value, str) or len(value) > 180 or not value.startswith("/") or
                "\x00" in value or any(x in (".", "..") for x in value.split("/"))):
            deny("invalid protected receiver path")
    folder = Path(policy["socket_path"]).parent
    state = Path(policy["state_root"])
    if state == folder or state in folder.parents or folder in state.parents:
        deny("receiver ledger and exposed socket cannot share a writable tree")
    if os.geteuid() == 0:
        deny("receiver must run under a non-root identity")
    return policy


def _validated_notice(raw: bytes, allowed_engagements):
    if not 0 < len(raw) <= MAX_MESSAGE or b"\n" in raw:
        deny("invalid bounded notification frame")
    try:
        msg = json.loads(raw)
    except (UnicodeError, ValueError, TypeError) as exc:
        raise ExecutionDenied("notification JSON rejected") from exc
    if (not isinstance(msg, dict) or set(msg) != REQUIRED or canonical(msg) != raw or
            msg["type"] != "aegis_assessment_v1" or
            not isinstance(msg["notice_id"], str) or not HEX.fullmatch(msg["notice_id"]) or
            not isinstance(msg["report_sha256"], str) or not HEX.fullmatch(msg["report_sha256"]) or
            not isinstance(msg["challenge"], str) or not CHALLENGE.fullmatch(msg["challenge"]) or
            not isinstance(msg["source_run_id"], str) or not ID.fullmatch(msg["source_run_id"]) or
            msg["engagement_id"] not in allowed_engagements or
            type(msg["lead_count"]) is not int or not 0 <= msg["lead_count"] <= 150 or
            msg["assessment_status"] not in ("limited_source_evidence_only",
                                              "independently_reviewed_limited_evidence")):
        deny("notification metadata rejected")
    return msg


class DurableReceiver:
    def __init__(self, policy_file: Path):
        self.policy_file = Path(policy_file)
        self.policy = _validated_policy(self.policy_file)
        self.state_root = Path(self.policy["state_root"])
        with open_directory_nofollow(self.state_root) as fd:
            private_directory(fd)
        self.path = Path(self.policy["socket_path"])

    def _database(self):
        path = self.state_root / "received.sqlite3"
        with open_directory_nofollow(self.state_root) as folder:
            private_directory(folder)
            fd = os.open(path.name, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=folder)
            try:
                st = os.fstat(fd)
                if (not stat.S_ISREG(st.st_mode) or st.st_uid != os.geteuid() or
                        st.st_mode & 0o077 or st.st_nlink != 1):
                    deny("receiver ledger is not private")
                os.fsync(folder)
            finally:
                os.close(fd)
        con = sqlite3.connect(str(path), timeout=5, isolation_level=None)
        con.execute("PRAGMA journal_mode=DELETE")
        con.execute("PRAGMA synchronous=FULL")
        con.execute("PRAGMA busy_timeout=5000")
        con.execute("""CREATE TABLE IF NOT EXISTS received (
            notice_id TEXT PRIMARY KEY, engagement_id TEXT NOT NULL,
            source_run_id TEXT NOT NULL, report_sha256 TEXT NOT NULL,
            lead_count INTEGER NOT NULL, assessment_status TEXT NOT NULL,
            received_utc TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')))""")
        return con

    def _commit_notice(self, msg):
        con = self._database()
        try:
            con.execute("BEGIN IMMEDIATE")
            previous = con.execute("""SELECT engagement_id,source_run_id,report_sha256,
                lead_count,assessment_status FROM received WHERE notice_id=?""",
                (msg["notice_id"],)).fetchone()
            payload = (msg["engagement_id"], msg["source_run_id"], msg["report_sha256"],
                       msg["lead_count"], msg["assessment_status"])
            if previous is not None and previous != payload:
                deny("notification replay conflicts with durable receipt")
            if previous is None:
                con.execute("""INSERT INTO received(notice_id,engagement_id,source_run_id,report_sha256,
                   lead_count,assessment_status) VALUES(?,?,?,?,?,?)""", (msg["notice_id"], *payload))
            con.commit()  # SQLite FULL synchronous commit precedes acknowledgement.
        finally:
            con.close()

    def handle(self, client):
        if not hasattr(socket, "SO_PEERCRED"):
            deny("Linux peer credentials required")
        pid, uid, gid = struct.unpack("3i", client.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
        if uid not in self.policy["allowed_sender_uids"]:
            deny("notification sender identity rejected")
        client.settimeout(3)
        buffer = b""
        while b"\n" not in buffer and len(buffer) <= MAX_MESSAGE:
            part = client.recv(256)
            if not part:
                break
            buffer += part
        if (len(buffer) > MAX_MESSAGE or buffer.count(b"\n") != 1 or not buffer.endswith(b"\n")):
            deny("invalid notification framing")
        msg = _validated_notice(buffer[:-1], self.policy["allowed_engagement_ids"])
        self._commit_notice(msg)
        ack = {"received": True, "notice_id": msg["notice_id"],
               "report_sha256": msg["report_sha256"], "challenge": msg["challenge"]}
        client.sendall(canonical(ack) + b"\n")

    def serve(self, *, stop_event=None):
        if stop_event is None:
            stop_event = threading.Event()
        policy = _validated_policy(self.policy_file)
        if policy != self.policy:
            deny("receiver policy changed before socket binding")
        with open_directory_nofollow(self.path.parent) as fd:
            st = os.fstat(fd)
            group_id = self.policy["shared_gid"]
            mode = stat.S_IMODE(st.st_mode)
            if (st.st_uid != os.geteuid() or
                    mode != (0o700 if group_id is None else 0o710) or
                    (group_id is not None and st.st_gid != group_id)):
                deny("receiver socket directory must be private and service-owned")
            if os.path.lexists(self.path):
                deny("receiver socket already exists; operator cleanup required")
        oldmask = os.umask(0o117 if self.policy["shared_gid"] is not None else 0o177)
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            sock.bind(str(self.path))
            os.chmod(self.path, 0o660 if self.policy["shared_gid"] is not None else 0o600)
            inode = os.stat(self.path, follow_symlinks=False)
            sock.listen(8)
            sock.settimeout(0.2)
            while not stop_event.is_set():
                try:
                    client, _ = sock.accept()
                except socket.timeout:
                    continue
                try:
                    with client:
                        try:self.handle(client)
                        except (OSError, ValueError, ExecutionDenied, sqlite3.Error):
                            pass  # Never tell an untrusted caller why it was denied.
                finally:
                    client.close()
        finally:
            sock.close()
            os.umask(oldmask)
            try:
                st = os.stat(self.path, follow_symlinks=False)
                if (st.st_dev, st.st_ino) == (inode.st_dev, inode.st_ino):
                    self.path.unlink()
            except (FileNotFoundError, UnboundLocalError):pass


def main():
    parser = argparse.ArgumentParser(description="AEGIS standalone private metadata notification receiver")
    parser.add_argument("--policy", type=Path, required=True)
    args = parser.parse_args()
    try:
        DurableReceiver(args.policy).serve()
    except (OSError, ValueError, ExecutionDenied, sqlite3.Error):
        print("RECEIVER_DENIED", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
