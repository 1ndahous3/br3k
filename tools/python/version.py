"""Staging version shared by wheel and CI native builds; no release tag required."""

import os
from datetime import date, datetime, timezone


def get_version() -> str:
    explicit = os.environ.get("BR3K_VERSION")
    if explicit:
        return explicit
    # Keep the native default in lib/build.rs: days since 2025-01-01.
    timestamp = os.environ.get("SOURCE_DATE_EPOCH")
    today = datetime.fromtimestamp(int(timestamp), timezone.utc).date() if timestamp else datetime.now(timezone.utc).date()
    return f"0.{(today - date(2025, 1, 1)).days}.0"


if __name__ == "__main__":
    print(get_version())
