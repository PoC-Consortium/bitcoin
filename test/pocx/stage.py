#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin PoCX developers
# Distributed under the MIT software license, see the accompanying file COPYING.
"""Build a disposable, hashed functional tree. Never write into upstream sources."""
import argparse
import configparser
import json
from pathlib import Path
import shutil
import subprocess

from common import ROOT, OWNED, sha256, short_tmpdir, build_options


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"Duplicate manifest key: {key}")
        result[key] = value
    return result


def framework_sources(root):
    """Include the upstream cryptographic test vectors alongside Python modules."""
    directory = root / 'test/functional'
    return {str(path.relative_to(directory)): path
            for path in sorted((directory / 'test_framework').rglob('*'))
            if path.is_file() and path.suffix in ('.py', '.csv') and '__pycache__' not in path.parts}


def stage(build, manifest_path=None):
    build = Path(build).resolve()
    cache = (build / "CMakeCache.txt").read_text()
    if "ENABLE_POCX:BOOL=ON\n" not in cache:
        raise ValueError("PoCX runner requires ENABLE_POCX=ON")
    if f"CMAKE_HOME_DIRECTORY:INTERNAL={ROOT}\n" not in cache:
        raise ValueError("Build must belong to this source worktree")
    if build == ROOT or not build.is_relative_to(ROOT):
        raise ValueError("Build must be a separate directory inside the isolated worktree")
    manifest = json.loads(Path(manifest_path or OWNED / "manifest.json").read_text(), object_pairs_hook=unique_object)
    if not manifest["tests"] and not manifest["reused_tests"]:
        raise ValueError("Empty test selection")
    sources = framework_sources(ROOT)
    for dest, source in manifest["replacements"].items():
        if dest not in sources:
            raise ValueError(f"Replacement has no upstream destination: {dest}")
        sources[dest] = OWNED / source
    for dest, source in manifest.get('framework_copies', {}).items():
        if dest in sources:
            raise ValueError(f'Conflicting framework copy destination: {dest}')
        original = (ROOT / 'test/functional' / source).resolve()
        if not original.is_relative_to(ROOT / 'test/functional/test_framework'):
            raise ValueError(f'Framework copy source outside upstream framework: {source}')
        sources[dest] = original
    for dest, source in manifest.get('support_copies', {}).items():
        if dest in sources:
            raise ValueError(f'Conflicting support copy destination: {dest}')
        destination = Path(dest)
        original = (ROOT / 'test/functional' / source).resolve()
        if (destination.is_absolute() or '..' in destination.parts or
                not destination.parts or destination.parts[0] not in ('data', 'mocks') or
                not original.is_relative_to(ROOT / 'test/functional' / destination.parts[0])):
            raise ValueError(f'Support copy outside upstream data/mocks: {dest}: {source}')
        sources[dest] = original
    for dest, source in manifest.get('support_replacements', {}).items():
        replacement = (OWNED / source).resolve()
        if dest not in manifest.get('support_copies', {}) or not replacement.is_relative_to(OWNED):
            raise ValueError(f'Unknown or escaping native support replacement: {dest}: {source}')
        sources[dest] = replacement
    for dest, source in manifest["tests"].items():
        if dest in sources:
            raise ValueError(f"Conflicting destination: {dest}")
        sources[dest] = OWNED / source
    for name in manifest["reused_tests"]:
        if name in sources:
            raise ValueError(f"Conflicting destination: {name}")
        sources[name] = ROOT / "test/functional" / name
    for dest, source in sources.items():
        if Path(dest).is_absolute() or ".." in Path(dest).parts or not source.is_file():
            raise ValueError(f"Invalid or missing source: {dest}: {source}")
    target = build / "pocx-functional"
    temporary = build / "pocx-functional.new"
    if temporary.exists():
        shutil.rmtree(temporary)
    temporary.mkdir()
    hashes = {}
    for dest, source in sorted(sources.items()):
        out = temporary / dest
        out.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, out)
        hashes[dest] = {"source": str(source.relative_to(ROOT)), "sha256": sha256(source)}
    config = configparser.ConfigParser()
    config.read(build / "test/config.ini")
    config["environment"]["SRCDIR"] = str(ROOT)
    config["environment"]["BUILDDIR"] = str(build)
    with (temporary / "config.ini").open("w") as stream:
        config.write(stream)
    provenance = {"revision": subprocess.check_output(["git", "-C", str(ROOT), "rev-parse", "HEAD"], text=True).strip(),
                  "build": str(build), "cache_sha256": sha256(build / "CMakeCache.txt"), "build_options": build_options(cache), "files": hashes}
    (temporary / "provenance.json").write_text(json.dumps(provenance, indent=2) + "\n")
    if target.exists():
        shutil.rmtree(target)
    temporary.rename(target)
    return target, manifest, provenance


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--build-dir", required=True)
    args = parser.parse_args()
    print(stage(args.build_dir)[0])
