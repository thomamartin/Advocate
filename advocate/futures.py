"""
Futures Session for Advocate.

This module provides a FuturesSession class that combines the async capabilities
of requests-futures with Advocate's security validation.
"""

from concurrent.futures import ThreadPoolExecutor
from typing import Any, Dict, Optional, TYPE_CHECKING

from requests.adapters import DEFAULT_POOLSIZE

if TYPE_CHECKING:
    from .api import Session

# Import requests_futures if available
try:
    import requests_futures.sessions
    HAVE_REQUESTS_FUTURES = True
except ImportError:
    HAVE_REQUESTS_FUTURES = False


def create_futures_session_class():
    """Create the FuturesSession class dynamically to avoid circular imports."""
    if not HAVE_REQUESTS_FUTURES:
        raise ImportError(
            "requests-futures is required for FuturesSession. "
            "Install it with: pip install requests-futures"
        )
    
    # Import here to avoid circular import
    from .api import Session
    
    class FuturesSession(requests_futures.sessions.FuturesSession, Session):
        """A FuturesSession with Advocate validation.
        
        This class combines the async capabilities of requests-futures
        with Advocate's security validation. It allows you to make
        asynchronous HTTP requests while still enforcing security policies.
        
        Example:
            >>> sess = FuturesSession(max_workers=20)
            >>> future = sess.get("http://example.com/")
            >>> response = future.result()
        
        Note:
            This class requires the requests-futures package to be installed.
            Install it with: pip install requests-futures
        """

        def __init__(
            self,
            executor: Optional[ThreadPoolExecutor] = None,
            max_workers: int = 2,
            session: Optional[Session] = None,
            *args: Any,
            **kwargs: Any
        ) -> None:
            """Initialize a FuturesSession with validation.
            
            Args:
                executor: ThreadPoolExecutor to use for async requests.
                max_workers: Maximum number of workers for the executor.
                session: Optional base Session to use.
                *args: Additional positional arguments.
                **kwargs: Additional keyword arguments.
                
            Raises:
                NotImplementedError: If session is not None and not an Advocate Session.
            """
            adapter_kwargs: Dict[str, Any] = {}
            if executor is None:
                executor = ThreadPoolExecutor(max_workers=max_workers)
                # set connection pool size equal to max_workers if needed
                if max_workers > DEFAULT_POOLSIZE:
                    adapter_kwargs = dict(
                        pool_connections=max_workers,
                        pool_maxsize=max_workers
                    )
            kwargs["_adapter_kwargs"] = adapter_kwargs
            Session.__init__(self, *args, **kwargs)
            requests_futures.sessions.FuturesSession.__init__(
                self, executor=executor, session=None
            )

        @property
        def session(self) -> None:
            """Get the underlying session (always None for Advocate)."""
            return None

        @session.setter
        def session(self, value: Any) -> None:
            """Set the underlying session.
            
            Args:
                value: The session to set.
                
            Raises:
                NotImplementedError: If value is not None and not an Advocate Session.
            """
            if value is not None and not isinstance(value, Session):
                raise NotImplementedError(
                    "Setting the .session property to "
                    "non-advocate values disabled "
                    "to prevent whitelist bypasses"
                )
    
    return FuturesSession


# Create the class if requests_futures is available
if HAVE_REQUESTS_FUTURES:
    FuturesSession = create_futures_session_class()
else:
    FuturesSession = None  # type: ignore
