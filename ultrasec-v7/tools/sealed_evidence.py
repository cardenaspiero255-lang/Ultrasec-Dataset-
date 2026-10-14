"""Internal-only sealed evidence I/O; never exposes benchmark verdict to caller stdout."""
from __future__ import annotations
import json
import os
from pathlib import Path
import stat


def _no_duplicates(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON key")
        result[key] = value
    return result


def read_jsonl(path: Path):
    """Reject duplicate properties, nonfinite values, huge rows and blank lines."""
    with path.open("r", encoding="utf-8") as stream:
        for line in stream:
            if len(line) > 1_000_000:
                raise ValueError("Overlong metadata line")
            yield json.loads(
                line, object_pairs_hook=_no_duplicates,
                parse_constant=lambda _: (_ for _ in ()).throw(ValueError("Nonfinite JSON")),
            )


def _exclusive(path: Path) -> int:
    """Create a single-use private file; no existing file or symlink may be replaced."""
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_NOFOLLOW", 0)
    return os.open(path, flags, 0o600)


def write_private(report_path: Path, lock_path: Path, report: dict) -> None:
    """Owner-only local report; session lock prevents accidental adaptive replay.

    The caller and its stdout are not an authorized results recipient. Session
    paths must be owner-controlled and non-reusable across candidate attempts.
    """
    if report_path.absolute() == lock_path.absolute():
        raise ValueError("Lock and report paths must differ")
    serialized = (json.dumps(report, sort_keys=True, ensure_ascii=True, allow_nan=False) + "\n").encode("utf-8")
    lock_fd = _exclusive(lock_path)
    try:
        os.write(lock_fd, b"sealed-session-v1\n")
        os.fsync(lock_fd)
    finally:
        os.close(lock_fd)
    report_fd = _exclusive(report_path)
    try:
        with os.fdopen(report_fd, "wb") as out:
            out.write(serialized)
            out.flush()
            os.fsync(out.fileno())
    except BaseException:
        # Never delete locks or overwrite existing reports on failure.
        raise


def public_receipt() -> str:
    """Stable success receipt: no labels, thresholds, score, pass/fail, or counts."""
    return json.dumps({"status": "SEALED"}, sort_keys=True)
