import logging.config
from pathlib import Path

import yaml


def setup_logger():
    root_dir = Path(__file__).parent.parent.parent
    logger_path = root_dir / "config" / "logging.yaml"
    with open(logger_path, "r") as logging_config:
        logging.config.dictConfig(yaml.load(logging_config, Loader=yaml.FullLoader))
