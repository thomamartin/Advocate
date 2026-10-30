from __future__ import annotations

from concurrent.futures import Executor
from typing import Any

from requests.adapters import DEFAULT_POOLSIZE
import requests_futures.sessions

from . import Session


class FuturesSession(requests_futures.sessions.FuturesSession, Session):
    def __init__(
        self,
        executor: Executor | None = None,
        max_workers: int = 2,
        session: Session | None = None,
        *args: Any,
        **kwargs: Any,
    ) -> None:
        if session is not None and not isinstance(session, Session):
            raise NotImplementedError(
                "Setting the .session property to "
                "non-advocate values disabled "
                "to prevent whitelist bypasses"
            )
        adapter_kwargs: dict[str, Any] = kwargs.pop("adapter_kwargs", None) or {}
        if executor is None and max_workers > DEFAULT_POOLSIZE:
            adapter_kwargs = {
                "pool_connections": max_workers,
                "pool_maxsize": max_workers,
                **adapter_kwargs,
            }
        kwargs["_adapter_kwargs"] = adapter_kwargs
        super().__init__(
            executor,
            max_workers,
            session,
            None,
            *args,
            **kwargs,
        )

    @property
    def session(self) -> None:
        return None

    @session.setter
    def session(self, value: Any) -> None:
        if value is not None and not isinstance(value, Session):
            raise NotImplementedError(
                "Setting the .session property to "
                "non-advocate values disabled "
                "to prevent whitelist bypasses"
            )
