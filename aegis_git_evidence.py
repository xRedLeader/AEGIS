"""Bounded Git object reads without checkout, hooks, filters or target execution."""
from pathlib import Path
import re
import subprocess
import time

from aegis_audit_contract import relative_path, require
from aegis_supervisor import ExecutionDenied


def read_commit(root, revision, paths=None, *, maximum_file=4*1024*1024, maximum_total=64*1024*1024, guard=lambda:None):
    require(isinstance(revision, str) and re.fullmatch(r"[a-f0-9]{40}", revision), "exact Git commit required")
    root = Path(root)
    env = {"PATH": "/usr/bin:/bin", "HOME": "/nonexistent", "GIT_CONFIG_NOSYSTEM": "1",
           "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_OPTIONAL_LOCKS": "0", "GIT_NO_REPLACE_OBJECTS": "1",
           "GIT_NO_LAZY_FETCH": "1", "GIT_TERMINAL_PROMPT": "0", "GIT_ALLOW_PROTOCOL": ""}
    argv = ["/usr/bin/git", "--no-optional-locks", "-C", str(root)]
    def git(args, data=None, expected_code=0):
        guard()
        worker = subprocess.Popen(argv+args, env=env, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                  stderr=subprocess.DEVNULL, close_fds=True)
        try:
            deadline, first = time.monotonic()+10, True
            while True:
                guard()
                require(time.monotonic() < deadline, "bounded Git object read timed out")
                try:
                    output, _ = worker.communicate(input=data if first else None, timeout=0.1)
                    break
                except subprocess.TimeoutExpired:
                    first = False
            guard()
            require(worker.returncode == expected_code, "bounded Git evidence read failed")
            return output
        finally:
            if worker.poll() is None:
                worker.kill(); worker.wait()
            for stream in (worker.stdin, worker.stdout):
                if stream: stream.close()
    # Older supported Git versions may ignore GIT_NO_LAZY_FETCH; reject promisor repositories too.
    require(not git(["config", "--includes", "--get-regexp", r"^(extensions\.partialclone|remote\..*\.promisor)$"], expected_code=1),
            "partial/promisor Git repositories are not offline evidence")
    require(git(["rev-parse", "--show-toplevel"]).decode().strip() == str(root.resolve()) and
            git(["cat-file", "-t", revision]) == b"commit\n", "selected history requires an exact repository-root commit")
    args = ["ls-tree", "-rlz", revision]
    if paths is not None:
        require(isinstance(paths, list) and 1 <= len(paths) <= 128 and paths == sorted(set(paths)), "bounded unique Git paths required")
        args += ["--", *[relative_path(p) for p in paths]]
    tree = git(args)
    require(0 < len(tree) <= 262144, "Git source tree exceeds bound or is empty")
    entries, total = [], 0
    for entry in tree.rstrip(b"\0").split(b"\0"):
        header, name = entry.split(b"\t", 1)
        mode, kind, oid, size = header.split()
        require(mode in {b"100644", b"100755"} and kind == b"blob" and re.fullmatch(b"[a-f0-9]{40}", oid),
                "Git source contains nonregular material")
        name = relative_path(name.decode("utf-8")); size = int(size)
        require(0 <= size <= maximum_file, "Git source file exceeds bound")
        entries.append((name, oid, size)); total += size
    require(1 <= len(entries) <= 512 and total <= maximum_total and
            (paths is None or {e[0] for e in entries} == set(paths)), "Git source inventory differs from selected bounds/paths")
    blobs = git(["cat-file", "--batch"], b"\n".join(e[1] for e in entries)+b"\n")
    offset, result = 0, {}
    for name, oid, size in entries:
        end = blobs.index(b"\n", offset)
        require(blobs[offset:end] == oid+b" blob "+str(size).encode(), "Git object differs from selected tree")
        start = end+1; body = blobs[start:start+size]
        require(len(body) == size and blobs[start+size:start+size+1] == b"\n", "truncated Git object")
        result[name] = body; offset = start+size+1
    require(offset == len(blobs), "unexpected Git object bytes")
    return result
