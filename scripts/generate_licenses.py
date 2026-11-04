#!/usr/bin/env python3
"""Snapshot licenses for the external Go modules compiled into release binaries.

Run from any directory: python3 scripts/generate_licenses.py [--check]
Requires the Go toolchain version declared in go.mod and downloaded modules.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
TARGETS = (("darwin", "amd64"), ("darwin", "arm64"), ("linux", "amd64"), ("linux", "arm64"))
LICENSE_NAME = re.compile(r"^(?:LICENSE|LICENCE|COPYING|NOTICE)(?:$|[-._].*)", re.I)
NON_TEXT_SUFFIXES = {".go", ".minisig", ".sig", ".asc"}


def go_output(*args: str, env: dict[str, str] | None = None) -> str:
    return subprocess.check_output(("go", *args), cwd=ROOT, env=env, text=True)


def compiled_modules() -> dict[str, tuple[str, Path]]:
    modules: dict[str, tuple[str, Path]] = {}
    template = "{{if .Module}}{{.Module.Path}}\t{{.Module.Version}}\t{{.Module.Dir}}{{end}}"
    for goos, goarch in TARGETS:
        env = {**os.environ, "GOOS": goos, "GOARCH": goarch, "CGO_ENABLED": "0"}
        for line in go_output("list", "-deps", "-f", template, "./cmd/abigail", env=env).splitlines():
            if not line:
                continue
            path, version, directory = line.split("\t", 2)
            if not version:  # Abigail itself, or a standard-library package.
                continue
            if not directory:
                raise RuntimeError(f"missing source directory for {path}@{version}")
            old = modules.setdefault(path, (version, Path(directory)))
            if old != (version, Path(directory)):
                raise RuntimeError(f"inconsistent dependency version for {path}")
    return modules


def legal_files(directory: Path) -> list[Path]:
    files = [
        path
        for path in directory.iterdir()
        if path.is_file()
        and LICENSE_NAME.match(path.name)
        and path.suffix.lower() not in NON_TEXT_SUFFIXES
    ]
    return sorted(files, key=lambda path: path.name)


def build_snapshot(destination: Path) -> int:
    modules = compiled_modules()
    destination.mkdir(parents=True)
    rows: list[str] = []
    for path, (version, directory) in sorted(modules.items()):
        if any(segment in ("", ".", "..") for segment in path.split("/")):
            raise RuntimeError(f"unsafe Go module path: {path}")
        files = legal_files(directory)
        if not files:
            raise RuntimeError(f"no root LICENSE, LICENCE, COPYING, or NOTICE for {path}@{version}")
        relative = Path("modules") / f"{path}@{version}"
        (destination / relative).mkdir(parents=True)
        links = []
        for source in files:
            target = destination / relative / source.name
            shutil.copyfile(source, target)
            links.append(f"[{source.name}]({(relative / source.name).as_posix()})")
        rows.append(f"| `{path}` | `{version}` | {', '.join(links)} |")

    goroot, goversion = go_output("env", "GOROOT", "GOVERSION").splitlines()
    go_dir = destination / "go" / goversion
    go_dir.mkdir(parents=True)
    go_files = []
    for name in ("LICENSE", "PATENTS"):
        source = Path(goroot) / name
        if source.is_file():
            shutil.copyfile(source, go_dir / name)
            go_files.append(f"[{name}](go/{goversion}/{name})")
    if not go_files or not (go_dir / "LICENSE").exists():
        raise RuntimeError(f"missing Go standard-library license in {goroot}")

    notice = "\n".join(
        [
            "# Dependency licenses",
            "",
            "This inventory covers the union of external Go modules compiled into Abigail's",
            "macOS and Linux release binaries (`amd64` and `arm64`, `CGO_ENABLED=0`).",
            "Exact upstream license and notice files are copied below without modification.",
            "Regenerate with `python3 scripts/generate_licenses.py`; verify with",
            "`python3 scripts/generate_licenses.py --check`.",
            "",
            f"The Go standard library (`{goversion}`) license and patent notice: {', '.join(go_files)}.",
            "The modified vendored Subfinder code and its upstream MIT notice are",
            "documented in [THIRD_PARTY_NOTICES.md](../THIRD_PARTY_NOTICES.md).",
            "",
            "| Module | Version | Upstream license / notice files |",
            "| --- | --- | --- |",
            *rows,
            "",
        ]
    )
    (destination / "NOTICE.md").write_text(notice)
    return len(modules)


def files_under(directory: Path) -> dict[Path, bytes]:
    return {path.relative_to(directory): path.read_bytes() for path in directory.rglob("*") if path.is_file()}


def main() -> int:
    check = sys.argv[1:] == ["--check"]
    if sys.argv[1:] not in ([], ["--check"]):
        print("usage: python3 scripts/generate_licenses.py [--check]", file=sys.stderr)
        return 2
    destination = ROOT / "licenses"
    with tempfile.TemporaryDirectory(prefix="abigail-licenses-") as scratch:
        staged = Path(scratch) / "licenses"
        count = build_snapshot(staged)
        if check:
            if not destination.exists() or files_under(destination) != files_under(staged):
                print("licenses/ is stale; run python3 scripts/generate_licenses.py", file=sys.stderr)
                return 1
        else:
            if destination.exists():
                shutil.rmtree(destination)
            shutil.move(staged, destination)
    print(f"licenses verified for {count} compiled external Go modules" if check else f"licenses generated for {count} compiled external Go modules")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
