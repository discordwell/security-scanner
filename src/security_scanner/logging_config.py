from __future__ import annotations

import logging
import logging.config


def setup_logging(level: str = "INFO") -> None:
    logging.config.dictConfig(
        {
            "version": 1,
            "disable_existing_loggers": False,
            "formatters": {
                "standard": {
                    "format": "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
                    "datefmt": "%Y-%m-%dT%H:%M:%S",
                },
            },
            "handlers": {
                "console": {
                    "class": "logging.StreamHandler",
                    "formatter": "standard",
                    "stream": "ext://sys.stderr",
                },
            },
            "root": {
                "level": level,
                "handlers": ["console"],
            },
            "loggers": {
                "security_scanner": {
                    "level": level,
                    "handlers": ["console"],
                    "propagate": False,
                },
            },
        }
    )
