#!/usr/bin/env python3
"""Return a safe binary filename from an app's Info.plist."""
import argparse
import plistlib
import re
from pathlib import Path


def app_name(info: dict) -> str:
    display = info.get("CFBundleDisplayName")
    executable = info.get("CFBundleExecutable")
    name = display if isinstance(display, str) and display.strip() else executable
    if not isinstance(name, str) or not name.strip():
        raise ValueError("Info.plist lacks CFBundleDisplayName and CFBundleExecutable")
    name = re.sub(r"[^\w.\-]+", "_", name.strip(), flags=re.UNICODE).strip("._-")
    if not name:
        raise ValueError("bundle name contains no safe filename characters")
    return name[:80]


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("plist", type=Path)
    args = parser.parse_args()
    with args.plist.open("rb") as stream:
        print(app_name(plistlib.load(stream)))


if __name__ == "__main__":
    main()
