import requests_futures.sessions

from . import Session


class FuturesSession(requests_futures.sessions.FuturesSession, Session):
    def __init__(self, executor=None, max_workers=2, session=None, **kwargs):
        # requests-futures sizes the connection pools by reconfiguring the
        # adapters already mounted on the session, so ours stay in place.
        # Requests always go through `self`, `session` is only validated.
        super().__init__(executor=executor, max_workers=max_workers, session=None, **kwargs)
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
