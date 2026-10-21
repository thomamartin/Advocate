import requests_futures.sessions

from . import Session


class FuturesSession(requests_futures.sessions.FuturesSession, Session):
    def __init__(self, executor=None, max_workers=2, session=None, **kwargs):
        # Requests always go through `self`, so reject other sessions upfront
        self.session = session
        # requests-futures sizes the connection pools by reconfiguring the
        # adapters already mounted on the session, so ours stay in place.
        super().__init__(executor=executor, max_workers=max_workers, **kwargs)

    @property
    def session(self):
        return None

    @session.setter
    def session(self, value):
        if value is not None:
            raise NotImplementedError("Passing a session to FuturesSession is disabled "
                                      "because its validator wouldn't be used, "
                                      "configure the FuturesSession instead")
