"""Bounded, hash-verified Git object reads without checkout or target execution."""

import hashlib
import os
from pathlib import Path
import re
import selectors
import signal
import subprocess
import time
from aegis_audit_contract import relative_path, require


def _bounded_command(argv, env, *, maximum, deadline, guard, data=None, expected_code=0):
    """Drain output while feeding stdin; enforce the limit before retaining bytes."""
    guard()
    require(time.monotonic() < deadline, "bounded Git object read timed out")
    worker = subprocess.Popen(argv, env=env, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                              stderr=subprocess.DEVNULL, close_fds=True, start_new_session=True)
    selector, output, sent, complete = selectors.DefaultSelector(), bytearray(), 0, False
    try:
        os.set_blocking(worker.stdout.fileno(), False)
        selector.register(worker.stdout, selectors.EVENT_READ)
        if data:
            os.set_blocking(worker.stdin.fileno(), False)
            selector.register(worker.stdin, selectors.EVENT_WRITE)
        else:
            worker.stdin.close()
        while selector.get_map() or worker.poll() is None:
            guard()
            require(time.monotonic() < deadline, "bounded Git object read timed out")
            for key, _ in selector.select(0.05):
                if key.fileobj is worker.stdout:
                    # Read at most one byte beyond the remaining allowance.
                    chunk = os.read(key.fd, min(65536, maximum-len(output)+1))
                    require(len(output)+len(chunk) <= maximum, "Git evidence output exceeds bound")
                    if chunk:
                        output.extend(chunk)
                    else:
                        selector.unregister(worker.stdout)
                else:
                    try:
                        sent += os.write(key.fd, data[sent:sent+65536])
                    except BrokenPipeError:
                        sent = len(data)
                    if sent == len(data):
                        selector.unregister(worker.stdin)
                        worker.stdin.close()
            if not selector.get_map() and worker.poll() is None:
                time.sleep(0.01)
        guard()
        require(worker.returncode == expected_code, "bounded Git evidence read failed")
        complete = True
        return bytes(output)
    finally:
        selector.close()
        if not complete:
            try:
                os.killpg(worker.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        try:
            worker.wait(timeout=1)
        except subprocess.TimeoutExpired:
            pass
        for stream in (worker.stdin, worker.stdout):
            stream.close()


def _verify_object(kind, oid, body):
    header = kind.encode("ascii")+b" "+str(len(body)).encode("ascii")+b"\0"
    require(hashlib.sha1(header+body).hexdigest() == oid, "Git object hash differs from requested identity")
    return body


def read_commit(root, revision, paths=None, *, maximum_file=4*1024*1024,
                maximum_total=64*1024*1024, guard=lambda: None):
    require(isinstance(revision, str) and re.fullmatch(r"[a-f0-9]{40}", revision), "exact Git commit required")
    require(type(maximum_file) is int and 0 < maximum_file <= 4*1024*1024 and
            type(maximum_total) is int and 0 < maximum_total <= 64*1024*1024, "invalid Git evidence bounds")
    if paths is not None:
        require(isinstance(paths, list) and 1 <= len(paths) <= 128 and
                all(isinstance(p, str) for p in paths) and paths == sorted(set(paths)), "bounded unique Git paths required")
        paths = [relative_path(p) for p in paths]
    root, deadline = Path(root), time.monotonic()+10
    env = {"PATH": "/usr/bin:/bin", "HOME": "/nonexistent", "GIT_CONFIG_NOSYSTEM": "1",
           "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_OPTIONAL_LOCKS": "0", "GIT_NO_REPLACE_OBJECTS": "1",
           "GIT_NO_LAZY_FETCH": "1", "GIT_TERMINAL_PROMPT": "0", "GIT_ALLOW_PROTOCOL": ""}
    argv = ["/usr/bin/git", "--no-optional-locks", "-C", str(root)]

    def git(args, maximum, data=None, expected_code=0):
        return _bounded_command(argv+args, env, maximum=maximum, deadline=deadline,
                                guard=guard, data=data, expected_code=expected_code)

    # Older supported Git versions may ignore GIT_NO_LAZY_FETCH. Reject these
    # repositories before any object access, including included local config.
    require(not git(["config", "--includes", "--get-regexp", r"^(extensions\.partialclone|remote\..*\.promisor)$"],
                    4096, expected_code=1), "partial/promisor Git repositories are not offline evidence")
    require(git(["rev-parse", "--show-toplevel"], 4096).decode().strip() == str(root.resolve()),
            "selected history requires an exact repository root")
    commit = _verify_object("commit", revision, git(["cat-file", "commit", revision], 65536))
    match = re.match(rb"tree ([a-f0-9]{40})\n", commit)
    require(match is not None, "Git commit tree is invalid")
    root_tree = match[1].decode("ascii")
    trees, metadata_bytes = {}, len(commit)

    def tree(oid):
        nonlocal metadata_bytes
        guard()
        if oid not in trees:
            require(len(trees) < 1024, "Git tree object count exceeds bound")
            raw = _verify_object("tree", oid, git(["cat-file", "tree", oid], 262144))
            metadata_bytes += len(raw)
            require(metadata_bytes <= 4*1024*1024, "Git tree metadata exceeds bound")
            entries, offset = {}, 0
            while offset < len(raw):
                space, nul = raw.find(b" ", offset), raw.find(b"\0", offset)
                require(offset < space < nul and nul+21 <= len(raw), "Git tree entry is invalid")
                mode = raw[offset:space]
                require(mode in {b"40000", b"100644", b"100755", b"120000", b"160000"}, "Git tree mode is invalid")
                name = relative_path(raw[space+1:nul].decode("utf-8"))
                require("/" not in name and name not in entries, "Git tree names are invalid or duplicated")
                entries[name] = (mode, raw[nul+1:nul+21].hex())
                offset = nul+21
            trees[oid] = entries
        return trees[oid]

    selected = {}
    if paths is not None:
        for name in paths:
            parts, oid = name.split("/"), root_tree
            require(len(parts) <= 64, "Git source path depth exceeds bound")
            for index, component in enumerate(parts):
                entries = tree(oid)
                require(component in entries, "Git source inventory differs from selected paths")
                mode, oid = entries[component]
                require(mode in ({b"100644", b"100755"} if index == len(parts)-1 else {b"40000"}),
                        "Git source contains nonregular material")
            selected[name] = oid
    else:
        pending, visits = [("", root_tree, 0)], 0
        while pending:
            prefix, oid, depth = pending.pop()
            visits += 1
            require(visits <= 1024 and depth < 64, "Git source directory traversal exceeds bound")
            for name, (mode, child) in tree(oid).items():
                name = relative_path(prefix+name)
                if mode == b"40000":
                    require(len(pending)+visits < 1024, "Git source directory traversal exceeds bound")
                    pending.append((name+"/", child, depth+1))
                else:
                    require(mode in {b"100644", b"100755"}, "Git source contains nonregular material")
                    require(len(selected) < 512, "Git source inventory exceeds bound")
                    selected[name] = child
    require(selected, "Git source inventory is empty")
    oids = sorted(set(selected.values()))
    request = b"".join(oid.encode("ascii")+b"\n" for oid in oids)
    headers = git(["cat-file", "--batch-check"], len(oids)*80, request).splitlines()
    require(len(headers) == len(oids), "Git object size inventory differs")
    sizes = {}
    for oid, header in zip(oids, headers):
        match = re.fullmatch(oid.encode("ascii")+rb" blob (0|[1-9][0-9]{0,9})", header)
        require(match is not None, "Git selected object is not a bounded blob")
        size = int(match[1])
        require(size <= maximum_file, "Git source file exceeds bound")
        sizes[oid] = size
    require(sum(sizes[oid] for oid in selected.values()) <= maximum_total, "Git source total exceeds bound")
    raw = git(["cat-file", "--batch"], sum(sizes.values())+len(oids)*80, request)
    blobs, offset = {}, 0
    for oid in oids:
        guard()
        end, size = raw.find(b"\n", offset, offset+80), sizes[oid]
        expected = oid.encode("ascii")+b" blob "+str(size).encode("ascii")
        require(end >= offset and raw[offset:end] == expected, "Git object differs from selected tree")
        start = end+1
        body = raw[start:start+size]
        require(len(body) == size and raw[start+size:start+size+1] == b"\n", "truncated Git object")
        blobs[oid] = _verify_object("blob", oid, body)
        offset = start+size+1
    require(offset == len(raw), "unexpected Git object bytes")
    guard()
    return {name: blobs[oid] for name, oid in sorted(selected.items())}
