import signal
import sys
from typing import Callable, Any


def signal_handler(sig: int, frame) -> None:
    """
    Signal handler function for graceful program termination.

    This function is designed to be registered with signal.signal() to handle
    interrupt signals (such as SIGINT from Ctrl+C) and terminate the program
    gracefully.

    Args:
        sig (int): The signal number that triggered the handler.
        frame (frame): The current stack frame at the time the signal was received.

    Returns:
        None: This function does not return as it exits the program.

    Example:
        >>> import signal
        >>> signal.signal(signal.SIGINT, signal_handler)
    """
    print('Exiting gracefully...')
    sys.exit(0)
    return


def register_sigint(handler: Callable[[int, Any], None]=signal_handler) -> None:
    """
    Register a signal handler for SIGINT (Ctrl+C).

    This function sets up the provided handler to be called when the program
    receives a SIGINT signal, allowing for graceful termination.

    Args:
        handler (Callable[[int, Any], None]): The function to be called when SIGINT is received.

    Returns:
        None: This function does not return any value.

    Example:
        >>> def my_handler(sig, frame):
        ...     print("Caught SIGINT!")
        ...     sys.exit(0)
        >>> register_sigint(my_handler)
    """
    signal.signal(signal.SIGINT, handler)  # type: ignore
    return