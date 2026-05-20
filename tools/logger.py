import logging, sys

_logger = None

def get_logger(name="ctf-agent"):
    global _logger
    if _logger:
        return _logger
    logger = logging.getLogger(name)
    logger.setLevel(logging.INFO)
    if not logger.handlers:
        h = logging.StreamHandler(sys.stdout)
        h.setFormatter(logging.Formatter(
            "[%(asctime)s] %(levelname)-5s %(message)s",
            datefmt="%H:%M:%S"
        ))
        logger.addHandler(h)
    _logger = logger
    return logger

setup_logger = get_logger