#!/usr/bin/env python3
# PYTHON_ARGCOMPLETE_OK

import argparse
import argcomplete
from pathlib import Path
from cli_core.log import setup_logging
from core.bootstrap import init

config = {
    "module_dependencies": ["a", "b", "c"],
    "system_dependencies": ["d", "e"],
    "argparse": {}
}

def parse_args():
    parser = argparse.ArgumentParser(
        description="",
        formatter_class=argparse.RawTextHelpFormatter
    )

    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose logging and save logs to file"
    )
    
    parser.add_argument(
        "--output", "-o",
        type=Path,
        help="Output fullpath to save debug logs to file"
    )

    subparsers = parser.add_subparsers(dest="command", required=True, help="Available commands")

    argcomplete.autocomplete(parser)

    return parser

def main():
    parser = parse_args()
    config["argparse"]["parser"] = parser
    config["argparse"]["args"] = parser.parse_args()
    result = init(config)
    operations = result.operations
    logger = getLogger(__name__)
    operations.dispatch()

if __name__ == "__main__":
    main()
