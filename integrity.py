"""Read-only, committed-source integrity checks. Never executes repository code."""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess

SHA = re.compile(r"^[a-f0-9]{40}$")
EMPTY_TREE = "4b825dc642cb6eb9a060e54bf8d69288fbee4904"
PATTERNS = {
    "private-key": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
    "github-token": re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"),
    "github-fine-grained-token": re.compile(r"\bgithub_pat_[A-Za-z0-9_]{60,}\b"),
    "stripe-live-key": re.compile(r"\bsk_live_[A-Za-z0-9]{20,}\b"),
}

def git(root: Path, *args: str) -> bytes:
    p = subprocess.run(["git", "-C", str(root), *args], capture_output=True, timeout=60)
    if p.returncode:
        raise ValueError(f"git {args[0]} failed (exit {p.returncode})")
    return p.stdout

def revision(root: Path, value: str) -> str:
    if not SHA.fullmatch(value):
        raise ValueError("revision must be a full lowercase Git SHA")
    return git(root, "rev-parse", "--verify", f"{value}^{{commit}}").decode().strip()

def audit(root: Path, base: str | None = None, max_bytes: int = 25*1024*1024) -> dict:
    if max_bytes <= 0:
        raise ValueError("max_bytes must be positive")
    head = revision(root, git(root, "rev-parse", "HEAD").decode().strip())
    if base and base != "0"*40:
        base = revision(root, base)
        # A changed base must actually precede the candidate, not suppress its changes.
        ancestor = subprocess.run(["git", "-C", str(root), "merge-base", "--is-ancestor", base, head], capture_output=True, timeout=60)
        if ancestor.returncode:
            raise ValueError("base is not an ancestor of candidate")
    else:
        parents = git(root, "rev-list", "--parents", "-n", "1", head).decode().split()
        base = parents[1] if len(parents)>1 else EMPTY_TREE
    if base == head:
        raise ValueError("base and candidate must differ")
    paths = git(root, "diff", "--name-only", "--no-renames", "--diff-filter=ACM", "-z", base, head, "--").split(b"\0")
    findings, checked = [], []
    for raw_path in filter(None, paths):
        path = raw_path.decode("utf-8", "surrogateescape")
        if "\n" in path or "\r" in path or "\x00" in path:
            findings.append({"path":repr(path),"code":"unsafe-path","severity":"block"})
            continue
        row = git(root, "ls-tree", "-z", head, "--", path).split(b"\0")[0]
        if not row:
            raise ValueError("changed blob missing from candidate")
        fields = row.split(b"\t",1)[0].decode().split()
        mode, kind, oid = fields
        if kind != "blob":
            continue
        size = int(git(root,"cat-file","-s",oid))
        checked.append({"path":path,"blob":oid,"bytes":size,"mode":mode})
        if size > max_bytes:
            findings.append({"path":path,"code":"oversize-blob","severity":"block"})
            continue
        content = git(root,"cat-file","blob",oid)
        checked[-1]["sha256"] = hashlib.sha256(content).hexdigest()
        if mode == "120000":
            target = content.decode("utf-8","replace")
            parts=list(PurePosixPath(path).parent.parts)
            unsafe=PurePosixPath(target).is_absolute() or "\\" in target
            for part in PurePosixPath(target).parts:
                if part=="..":
                    if not parts: unsafe=True
                    else: parts.pop()
                elif part!=".": parts.append(part)
            if unsafe:
                findings.append({"path":path,"code":"external-symlink","severity":"block"})
        diff=git(root,"diff","--no-ext-diff","--no-textconv","--unified=0",base,head,"--",path).decode("utf-8","replace")
        added="\n".join(line[1:] for line in diff.splitlines() if line.startswith("+") and not line.startswith("+++"))
        for code, pattern in PATTERNS.items():
            if pattern.search(added):
                findings.append({"path":path,"code":code,"severity":"block"})
    digest=hashlib.sha256(json.dumps(checked,sort_keys=True,separators=(",",":")).encode()).hexdigest()
    return {"schema":"blacklabel.source-integrity.v1", "observed_at":dt.datetime.now(dt.timezone.utc).isoformat(),
            "repository":os.environ.get("GITHUB_REPOSITORY","local"),"source_revision":head,"base_revision":base,
            "status":"failed" if findings else "passed","checked_blobs":checked,"checked_manifest_sha256":digest,
            "findings":findings,"scope":"changed-committed-source-only","product_tests":"not_checked",
            "runtime_acceptance":"not_checked","release_authorized":False}

def main() -> int:
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--root",type=Path,default=Path.cwd())
    p.add_argument("--base",default=os.environ.get("BASE_SHA") or None)
    p.add_argument("--output",type=Path,required=True)
    args=p.parse_args()
    try:
        result=audit(args.root,args.base)
    except (ValueError, subprocess.TimeoutExpired, OSError) as exc:
        result={"schema":"blacklabel.source-integrity.v1","status":"error","reason":str(exc),"release_authorized":False}
    args.output.parent.mkdir(parents=True,exist_ok=True)
    args.output.write_text(json.dumps(result,indent=2)+"\n",encoding="utf-8")
    print(json.dumps({k:v for k,v in result.items() if k!="checked_blobs"}))
    return 0 if result["status"]=="passed" else 1

if __name__=="__main__":
    raise SystemExit(main())
