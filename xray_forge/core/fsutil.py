"""Small filesystem helpers shared by the core modules."""

from __future__ import annotations

import os
import tempfile


def write_private(path: str, data: bytes | str, mode: int = 0o600) -> str:
    """Atomically write ``data`` to ``path`` readable only by the owner.

    The temp file is created with ``mode`` from the start (no window where a
    secret is world-readable) and then renamed over the target.  On Windows
    the mode bits are largely ignored, which is the best the OS offers here.
    """
    if isinstance(data, str):
        data = data.encode("utf-8")
    directory = os.path.dirname(os.path.abspath(path))
    os.makedirs(directory, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=directory, prefix=".tmp-")
    try:
        try:
            os.fchmod(fd, mode)
        except (AttributeError, OSError):
            pass
        with os.fdopen(fd, "wb") as f:
            f.write(data)
        os.replace(tmp, path)
        try:
            os.chmod(path, mode)
        except OSError:
            pass
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    return path
