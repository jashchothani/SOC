"""
Centralized exception management, graceful module degradation, alerts, and retry handlers.
"""
import time
import sys
import traceback
from typing import Callable, Any, Type, Tuple
from utils.logger import logger
from utils.timestamp import get_utc_timestamp
from config.constants import SEVERITY_CRITICAL, SEVERITY_ERROR, EVENT_SYSTEM_ALERT

# Callback definition to log exception events to the event database
_alert_callback = None

def register_alert_callback(callback: Callable[[dict], None]):
    """Registers a callback function to write critical alerts to the system's JSON event stream."""
    global _alert_callback
    _alert_callback = callback

def handle_exception(
    exc: Exception, 
    module_name: str, 
    message: str = "An error occurred", 
    severity: str = SEVERITY_ERROR
):
    """
    Centralized exception logging and event alert generation.
    Logs call stack and triggers callback alerts for critical failures.
    """
    exc_type, exc_value, exc_traceback = sys.exc_info()
    tb_str = "".join(traceback.format_exception(exc_type, exc_value, exc_traceback))
    
    log_msg = f"[{module_name}] {message}: {exc}\nTraceback:\n{tb_str}"
    
    if severity == SEVERITY_CRITICAL:
        logger.critical(log_msg)
    else:
        logger.error(log_msg)
        
    # Generate system event if callback is active
    if _alert_callback:
        import uuid
        alert_event = {
            "event_id": f"EVT-{uuid.uuid4()}",
            "timestamp": get_utc_timestamp(),
            "module": module_name,
            "event_type": EVENT_SYSTEM_ALERT,
            "severity": severity,
            "status": "failed",
            "data": {
                "error_type": exc.__class__.__name__,
                "error_message": str(exc),
                "context": message
            }
        }
        try:
            _alert_callback(alert_event)
        except Exception as callback_err:
            logger.error(f"Failed to submit system alert event: {callback_err}")

def retry_on_exception(
    retries: int = 3,
    backoff_factor: float = 2.0,
    exceptions: Tuple[Type[Exception], ...] = (Exception,)
):
    """
    Decorator that retries a function if it raises specified exceptions.
    Implements exponential backoff.
    """
    def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
        def wrapper(*args, **kwargs) -> Any:
            attempt = 0
            delay = 1.0
            while attempt < retries:
                try:
                    return func(*args, **kwargs)
                except exceptions as e:
                    attempt += 1
                    if attempt >= retries:
                        logger.error(f"Retry limit ({retries}) reached for {func.__name__} in {func.__module__}. Final exception: {e}")
                        raise
                    logger.warning(
                        f"Exception in {func.__name__} (Attempt {attempt}/{retries}): {e}. "
                        f"Retrying in {delay:.1f} seconds..."
                    )
                    time.sleep(delay)
                    delay *= backoff_factor
            return None
        return wrapper
    return decorator

def run_gracefully(module_name: str, default_return: Any = None) -> Callable:
    """
    Decorator to wrap a module execution and return a default value on error,
    preventing module crashes from terminating the main orchestrator threads.
    """
    def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
        def wrapper(*args, **kwargs) -> Any:
            try:
                return func(*args, **kwargs)
            except Exception as e:
                handle_exception(
                    exc=e,
                    module_name=module_name,
                    message=f"Graceful degradation triggered in {func.__name__}",
                    severity=SEVERITY_ERROR
                )
                return default_return
        return wrapper
    return decorator
