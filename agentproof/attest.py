"""Independent filesystem postflight observer for Terraform local_file sandbox pilots.

Checks actual filesystem bytes (not Terraform state or agent success text).
Uses Linux/POSIX dirfd and O_NOFOLLOW to reject symlink traversal.
"""
import hashlib
import os
import re
import stat
from pathlib import Path
from .engine import digest

SCHEMA = "agent-proof-pack/file-expectations/v1"
MAX_BYTES = 64 * 1024 * 1024
HEX = re.compile(r"^[a-f0-9]{64}$")


class ObservationError(ValueError):
    """Unable to establish an independent observation."""


def validate_expectations(spec):
    if not isinstance(spec, dict) or set(spec) != {"schema", "files"} or spec["schema"] != SCHEMA:
        raise ObservationError("invalid expectation schema")
    items = spec["files"]
    if not isinstance(items, list) or not 1 <= len(items) <= 32:
        raise ObservationError("require 1–32 file expectations")
    seen = set()
    for item in items:
        if not isinstance(item, dict) or set(item) != {"path", "sha256"}:
            raise ObservationError("invalid expectation record")
        name, sha = item["path"], item["sha256"]
        if (not isinstance(name, str) or len(name) > 512 or name.startswith("/") or
            "\\" in name or any(p in ("", ".", "..") for p in name.split("/")) or
            name in seen or not isinstance(sha, str) or not HEX.fullmatch(sha)):
            raise ObservationError("unsafe path, duplicate, or hash")
        seen.add(name)


def _file_hash(root_fd, relative):
    parts = relative.split("/")
    parent_fd = os.dup(root_fd)
    try:
        for part in parts[:-1]:
            new_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                             dir_fd=parent_fd)
            os.close(parent_fd)
            parent_fd = new_fd
        fd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                     dir_fd=parent_fd)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_BYTES:
                raise ObservationError("not a bounded regular file")
            sha = hashlib.sha256()
            count = 0
            while True:
                data = os.read(fd, 1024 * 1024)
                if not data:
                    break
                count += len(data)
                if count > MAX_BYTES:
                    raise ObservationError("file exceeds observation limit")
                sha.update(data)
            return sha.hexdigest(), count
        finally:
            os.close(fd)
    finally:
        os.close(parent_fd)


def observe_files(root, expectations):
    validate_expectations(expectations)
    root = Path(root)
    if root.is_symlink() or not root.is_dir() or not hasattr(os, "O_NOFOLLOW"):
        raise ObservationError("unsupported/symlinked observation root")
    records = []
    root_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for item in expectations["files"]:
            record = {"path": item["path"]}
            try:
                actual, size = _file_hash(root_fd, item["path"])
                record["observed_sha256"] = actual
                record["size_bytes"] = size
                record["status"] = "pass" if actual == item["sha256"] else "fail"
            except (OSError, ObservationError):
                record["status"] = "fail"
                record["reason"] = "independent observation unavailable"
            records.append(record)
    finally:
        os.close(root_fd)
    receipt = {"schema": "agent-proof-pack/filesystem-observation/v1",
               "expectations_sha256": digest(expectations),
               "state": "verified" if all(r["status"] == "pass" for r in records) else "mismatch",
               "observations": records,
               "limits": "Filesystem evidence only; not a cloud API or Terraform-state attestation."}
    receipt["receipt_sha256"] = digest(receipt)
    return receipt