import logging
import sys
import time
from pathlib import Path
from logging.handlers import RotatingFileHandler
from functools import wraps

# Setup base logs directory relative to current file
LOGS_DIR = Path(__file__).parent.parent / "logs"

def setup_logger(name: str = "ml-engine", level: int = logging.INFO) -> logging.Logger:
    """Sets up a standardized rotating file and console logger for the ML engine."""
    logger = logging.getLogger(name)
    if logger.handlers:
        return logger
        
    logger.setLevel(level)
    
    # Setup formatter
    formatter = logging.Formatter(
        "[%(asctime)s] %(levelname)s [%(name)s:%(filename)s:%(lineno)d] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )
    
    # 1. Console Handler (stdout)
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)
    
    # 2. Rotating File Handler
    try:
        LOGS_DIR.mkdir(parents=True, exist_ok=True)
        log_file = LOGS_DIR / "ml-engine.log"
        
        # Rotates file at 10MB, keeping up to 5 historical backups
        file_handler = RotatingFileHandler(
            log_file,
            maxBytes=10 * 1024 * 1024,
            backupCount=5,
            encoding="utf-8"
        )
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
    except Exception as e:
        # Fallback if logs directory cannot be written to
        logger.warning(f"Failed to initialize rotating file handler: {e}")
        
    return logger

def timed(logger_instance=None):
    """Decorator to measure and log execution duration of functions."""
    log = logger_instance or setup_logger("timing-decorator")
    
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            start_time = time.time()
            try:
                result = func(*args, **kwargs)
                duration = time.time() - start_time
                log.info(f"Function '{func.__name__}' completed in {duration:.4f} seconds.")
                return result
            except Exception as e:
                duration = time.time() - start_time
                log.error(f"Function '{func.__name__}' failed after {duration:.4f} seconds with error: {e}")
                raise e
        return wrapper
    return decorator
