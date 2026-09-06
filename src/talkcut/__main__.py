"""Command-line entry point. Media processing is not implemented yet."""

import argparse
from importlib.metadata import version


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="talkcut",
        description=(
            "Talkcut: an agent-driven lecture and podcast editing workflow. "
            "Initial scaffold only; media processing commands are not implemented."
        ),
    )
    parser.add_argument(
        "--version", action="version", version=f"%(prog)s {version('talkcut')}"
    )
    parser.parse_args()
    parser.print_help()


if __name__ == "__main__":
    main()
