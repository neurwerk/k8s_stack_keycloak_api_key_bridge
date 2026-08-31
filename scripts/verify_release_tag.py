"""Verify that a release tag agrees with all Python version sources."""

from __future__ import annotations

import re
import sys
import tomllib
from collections.abc import Sequence
from pathlib import Path

PROJECT_FILE = Path(__file__).resolve().parents[1] / "pyproject.toml"
LOCK_FILE = PROJECT_FILE.with_name("uv.lock")
TAG_PATTERN = re.compile(r"v(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\Z")


def load_project_metadata(project_file: Path) -> tuple[str, str]:
    """Read the static project name and version."""
    with project_file.open("rb") as file:
        project = tomllib.load(file).get("project")
    if not isinstance(project, dict):
        raise ValueError("pyproject.toml has no [project] table")
    name = project.get("name")
    version = project.get("version")
    if not isinstance(name, str) or not name:
        raise ValueError("pyproject.toml has no project.name")
    if not isinstance(version, str) or not version:
        raise ValueError("pyproject.toml has no static project.version")
    return name, version


def load_project_version(project_file: Path) -> str:
    """Read the static project version."""
    return load_project_metadata(project_file)[1]


def load_lock_version(lock_file: Path, project_name: str) -> str:
    """Read the version of the editable root package from uv.lock."""
    with lock_file.open("rb") as file:
        packages = tomllib.load(file).get("package")
    if not isinstance(packages, list):
        raise ValueError(f"uv.lock has no unique editable root package for {project_name!r}")
    versions = []
    for package in packages:
        if not isinstance(package, dict) or package.get("name") != project_name:
            continue
        source = package.get("source")
        if isinstance(source, dict) and source.get("editable") == ".":
            versions.append(package.get("version"))
    if len(versions) != 1 or not isinstance(versions[0], str) or not versions[0]:
        raise ValueError(f"uv.lock has no unique editable root package for {project_name!r}")
    return versions[0]


def verify_release_tag(
    tag: str, project_file: Path = PROJECT_FILE, lock_file: Path = LOCK_FILE
) -> str:
    """Return the verified tag or reject inconsistent release metadata."""
    if TAG_PATTERN.fullmatch(tag) is None:
        raise ValueError(f"release tag {tag!r} must match vX.Y.Z")
    project_name, project_version = load_project_metadata(project_file)
    lock_version = load_lock_version(lock_file, project_name)
    if project_version != lock_version:
        raise ValueError(
            "pyproject.toml version "
            f"{project_version!r} does not match uv.lock version {lock_version!r}"
        )
    expected = f"v{project_version}"
    if tag != expected:
        raise ValueError(f"release tag {tag!r} does not match project version {expected!r}")
    return tag


def main(argv: Sequence[str] | None = None) -> int:
    """Run the release-tag check from the command line."""
    arguments = list(sys.argv[1:] if argv is None else argv)
    if len(arguments) != 1:
        sys.stderr.write("usage: verify_release_tag.py <tag>\n")
        return 2
    try:
        verified = verify_release_tag(arguments[0])
    except (OSError, tomllib.TOMLDecodeError, ValueError) as exc:
        sys.stderr.write(f"release version check failed: {exc}\n")
        return 1
    sys.stdout.write(f"release tag matches pyproject.toml and uv.lock: {verified}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
