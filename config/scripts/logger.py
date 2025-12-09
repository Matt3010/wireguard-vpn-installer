import logging
import traceback
from logging.handlers import RotatingFileHandler
from config import LOGFILE, SEPARATOR_LINE

# Configure Logger with Rotation
# Max size: 5 MB, Backup count: 1
# This prevents the log file from filling up the disk indefinitely.
handler = RotatingFileHandler(LOGFILE, maxBytes=5*1024*1024, backupCount=1)
handler.setFormatter(logging.Formatter('%(asctime)s - %(message)s', '%Y-%m-%d %H:%M:%S'))

logger = logging.getLogger()
logger.setLevel(logging.INFO)
logger.addHandler(handler)

def log_msg(message):
    """Logs to file (rotating) and prints to stdout."""
    print(message)
    logging.info(message)

def log_separator():
    """Inserts a visual separator into the log."""
    sep = f"\n{SEPARATOR_LINE}"
    print(sep)
    # We use logging.info to ensure it goes through the rotation handler
    logging.info(SEPARATOR_LINE)

def log_error(context, exception_obj):
    """Logs full traceback for debugging."""
    err_msg = f"[ERROR] {context}: {exception_obj}"
    print(err_msg)
    logging.error(err_msg)

    tb_str = traceback.format_exc()
    # Log traceback directly to the file via handler logic
    logging.error(f"--- TRACEBACK START ---\n{tb_str}--- TRACEBACK END ---")
}