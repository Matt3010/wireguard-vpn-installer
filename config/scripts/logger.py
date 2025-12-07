import logging
import traceback
from config import LOGFILE, SEPARATOR_LINE

# Configure Logging once on import
logging.basicConfig(
    filename=LOGFILE,
    filemode='a',
    level=logging.INFO,
    format='%(asctime)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

def log_msg(message):
    """Logs to file and prints to stdout."""
    print(message)
    logging.info(message)

def log_separator():
    """Inserts a visual separator into the log."""
    sep = f"\n{SEPARATOR_LINE}"
    print(sep)
    with open(LOGFILE, "a") as f:
        f.write(f"{sep}\n")

def log_error(context, exception_obj):
    """Logs full traceback for debugging."""
    err_msg = f"[ERROR] {context}: {exception_obj}"
    print(err_msg)
    logging.error(err_msg)

    tb_str = traceback.format_exc()
    with open(LOGFILE, "a") as f:
        f.write(f"--- TRACEBACK START ---\n{tb_str}--- TRACEBACK END ---\n")