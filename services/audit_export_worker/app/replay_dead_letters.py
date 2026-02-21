from __future__ import annotations

import argparse

from .db import ensure_schema
from .exporter import replay_dead_letters_once


def main():
    parser = argparse.ArgumentParser(description="Replay pending audit export dead letters.")
    parser.add_argument("--limit", type=int, default=200)
    args = parser.parse_args()

    ensure_schema()
    success, failed = replay_dead_letters_once(limit=args.limit)
    print(f"replay_success={success} replay_failed={failed}")


if __name__ == "__main__":
    main()
