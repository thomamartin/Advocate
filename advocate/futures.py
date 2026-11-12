import requests_futures.sessions
from concurrent.futures import ThreadPoolExecutor
from threading import Lock
from requests.adapters import DEFAULT_POOLSIZE

from . import Session


class FuturesSession(requests_futures.sessions.FuturesSession, Session):
    def __init__(self, executor=None, max_workers=2, session=None, *args,
                 **kwargs):
        adapter_kwargs = {}
        if executor is None:
            executor = ThreadPoolExecutor(max_workers=max_workers)
            # set connection pool size equal to max_workers if needed
            if max_workers > DEFAULT_POOLSIZE:
                adapter_kwargs = dict(pool_connections=max_workers,
                                      pool_maxsize=max_workers)
        kwargs["_adapter_kwargs"] = adapter_kwargs
        # `requests-futures` 1.0+ tracks state about owned executors and
        # pending futures in `__init__()`; we bypass it, so set up the
        # attributes it expects ourselves.
        self._owned_executor = executor is None
        self._pending_futures = set()
        self._pending_futures_lock = Lock()
        self._close_lock = Lock()
        self._closed = False
        Session.__init__(self, *args, **kwargs)
        self.executor = executor
        self.session = session

    @property
    def session(self):
        return None

    @session.setter
    def session(self, value):
        if value is not None and not isinstance(value, Session):
            raise NotImplementedError("Setting the .session property to "
                                      "non-advocate values disabled "
                                      "to prevent whitelist bypasses")
