"""One OS-held controller lease per project, released even on process death."""

from __future__ import annotations

import fcntl
import json
import os
from pathlib import Path


class ProjectLock:
    def __init__(self, workspace: Path):
        # Never unlink this file: waiters must lock the same inode.
        self.path = workspace / ".controller.lock"
        self.handle = self.path.open("a+", encoding="utf-8")
        try:
            fcntl.flock(self.handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            self.handle.seek(0)
            owner = self.handle.read(2048)
            self.handle.close()
            raise RuntimeError(
                "Project already has an active controller (%s). "
                "Use a different project or wait for its controller to exit." % owner
            ) from None
        except BaseException:
            self.handle.close()
            raise
        try:
            self.handle.seek(0)
            self.handle.truncate()
            self.handle.write(json.dumps({"pid": os.getpid()}))
            self.handle.flush()
        except BaseException:
            self.close()
            raise

    def close(self) -> None:
        if not self.handle.closed:
            fcntl.flock(self.handle.fileno(), fcntl.LOCK_UN)
            self.handle.close()
