from __future__ import annotations

from collections.abc import Iterator
import contextlib
import os.path
import socket
import traceback
from typing import Any, ClassVar


class DisallowedConnectException(Exception):
    pass


class CheckedSocket(socket.socket):
    CONNECT_ALLOWED_FUNCS: ClassVar[set[str]] = {"validating_create_connection"}
    # `test_testserver.py` makes raw connections to the test server to ensure it works
    CONNECT_ALLOWED_FILES: ClassVar[set[str]] = {"test_testserver.py"}
    _checks_enabled: ClassVar[bool] = True

    @classmethod
    @contextlib.contextmanager
    def bypass_checks(cls) -> Iterator[None]:
        try:
            cls._checks_enabled = False
            yield
        finally:
            cls._checks_enabled = True

    @classmethod
    def _check_frame_allowed(cls, frame: traceback.FrameSummary | tuple[Any, ...]) -> bool:
        filename = frame.filename if isinstance(frame, traceback.FrameSummary) else frame[0]
        funcname = frame.name if isinstance(frame, traceback.FrameSummary) else frame[2]
        if os.path.basename(filename) in cls.CONNECT_ALLOWED_FILES:
            return True
        return funcname in cls.CONNECT_ALLOWED_FUNCS

    def connect(self, *args: Any, **kwargs: Any) -> None:
        if self._checks_enabled:
            stack = traceback.extract_stack()
            if not any(self._check_frame_allowed(frame) for frame in stack):
                raise DisallowedConnectException("calling socket.connect() unsafely!")
        return super().connect(*args, **kwargs)
