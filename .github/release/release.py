"""Validate release sources and package and verify the distributed files."""

import argparse
import gzip
import hashlib
import json
import os
import re
import shutil
import subprocess
import tarfile
import tempfile
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TARGETS = (
    "x86_64-unknown-linux-gnu",
    "x86_64-unknown-linux-musl",
    "aarch64-unknown-linux-gnu",
    "x86_64-apple-darwin",
    "aarch64-apple-darwin",
)


def git(root: Path, *args: str) -> str:
    """Run Git in the source checkout.

    Args:
        root (Path): Checkout directory.
        *args (str): Git arguments.

    Returns:
        str: Standard output with trailing whitespace removed.

    Raises:
        subprocess.CalledProcessError: Git rejects the operation.
    """
    return subprocess.check_output(["git", *args], cwd=root, text=True).strip()


def validate_tag(tag: str, version: str) -> None:
    """Require a version tag matching the Cargo package.

    Args:
        tag (str): Release tag, including its v prefix.
        version (str): Cargo package version.

    Raises:
        ValueError: The tag is malformed or differs from the package version.
    """
    if not re.fullmatch(r"v\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?", tag):
        raise ValueError(
            "release tag must be vMAJOR.MINOR.PATCH with an optional prerelease"
        )
    if tag != f"v{version}":
        raise ValueError("release tag does not match Cargo.toml")


def plan(root: Path, tag: str, preview: bool) -> tuple[str, str]:
    """Resolve the immutable source revision for a release or PR build.

    Args:
        root (Path): Checkout with fetched tags and origin/main.
        tag (str): Existing release tag; unused for a PR preview.
        preview (bool): Whether to build the checked-out PR revision.

    Returns:
        tuple[str, str]: Validated tag and source commit SHA.

    Raises:
        ValueError: The tag/version is invalid or its commit is outside main.
        subprocess.CalledProcessError: A required Git ref is unavailable.
    """
    if preview:
        manifest = tomllib.loads((root / "Cargo.toml").read_text())
        tag = f"v{manifest['package']['version']}"
        commit = git(root, "rev-parse", "HEAD")
    else:
        # Validate before using the supplied tag as a Git revision.
        validate_tag(tag, tag.removeprefix("v"))
        commit = git(root, "rev-parse", "--verify", f"refs/tags/{tag}^{{commit}}")
        if subprocess.run(
            ["git", "merge-base", "--is-ancestor", commit, "origin/main"],
            cwd=root,
            check=False,
        ).returncode:
            raise ValueError("release tag must point to a commit reachable from main")
        manifest = tomllib.loads(git(root, "show", f"{commit}:Cargo.toml"))
    validate_tag(tag, manifest["package"]["version"])
    return tag, commit


def archive_names(tag: str) -> set[str]:
    """Return the complete set of versioned archive names.

    Args:
        tag (str): Validated release tag.

    Returns:
        set[str]: One archive filename for each supported target.
    """
    return {f"postmaster-{tag}-{target}.tar.gz" for target in TARGETS}


def verify_archive(path: Path, root: Path | None = None) -> None:
    """Check archive contents and optionally execute the extracted binary.

    Args:
        path (Path): Release archive to inspect.
        root (Path | None): Source checkout for an optional packaged-binary smoke check.

    Raises:
        ValueError: Entries include unexpected paths, links, or permissions.
        subprocess.CalledProcessError: The packaged binary fails its smoke check.
    """
    with tarfile.open(path, "r:gz") as archive:
        members = archive.getmembers()
        if [entry.name for entry in members] != ["postmaster", "LICENSE"]:
            raise ValueError("archive must contain exactly postmaster and LICENSE")
        if any(not entry.isfile() for entry in members):
            raise ValueError("archive entries must be regular files")
        if [entry.mode for entry in members] != [0o755, 0o644]:
            raise ValueError("archive permissions differ from the release contract")
        if root is not None:
            with tempfile.TemporaryDirectory(prefix="postmaster-release-") as directory:
                binary = Path(directory) / "postmaster"
                with (
                    archive.extractfile(members[0]) as source,
                    binary.open("wb") as output,
                ):
                    shutil.copyfileobj(source, output)
                binary.chmod(0o755)
                version = tomllib.loads((root / "Cargo.toml").read_text())["package"][
                    "version"
                ]
                actual = subprocess.check_output(
                    [str(binary), "--version"], text=True
                ).strip()
                if actual != f"postmaster {version}":
                    raise ValueError("packaged binary reports the wrong version")
                subprocess.run(
                    [
                        str(binary),
                        "exec",
                        "--config",
                        str(root / "docs/examples/exec-env.json"),
                        "--check",
                    ],
                    check=True,
                )


def package(root: Path, target: str) -> Path:
    """Package a built release binary and smoke-test the resulting archive.

    Args:
        root (Path): Built source checkout.
        target (str): Supported Rust target triple.

    Returns:
        Path: Verified archive under target/release-artifacts.

    Raises:
        ValueError: The target or binary type is invalid, or verification fails.
        OSError: An input cannot be read or the archive cannot be written.
    """
    if target not in TARGETS:
        raise ValueError("unsupported release target")
    version = tomllib.loads((root / "Cargo.toml").read_text())["package"]["version"]
    tag = f"v{version}"
    validate_tag(tag, version)
    binary = root / "target" / target / "release/postmaster"
    if binary.is_symlink() or not binary.is_file():
        raise ValueError("release binary must be a regular file")
    directory = root / "target/release-artifacts"
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / f"postmaster-{tag}-{target}.tar.gz"
    timestamp = int(git(root, "show", "-s", "--format=%ct", "HEAD"))
    with (
        path.open("wb") as output,
        gzip.GzipFile(fileobj=output, mode="wb", filename="", mtime=0) as compressed,
        tarfile.open(fileobj=compressed, mode="w") as archive,
    ):
        for source, name, mode in [
            (binary, "postmaster", 0o755),
            (root / "LICENSE", "LICENSE", 0o644),
        ]:
            info = tarfile.TarInfo(name)
            info.size = source.stat().st_size
            info.mode = mode
            info.mtime = timestamp
            with source.open("rb") as data:
                archive.addfile(info, data)
    verify_archive(path, root)
    return path


def release_files(directory: Path, tag: str, commit: str, verify: bool) -> None:
    """Create or verify a complete release manifest and its bound source metadata.

    Args:
        directory (Path): Release files, without nested directories.
        tag (str): Release tag matching the source manifest.
        commit (str): Exact tagged source commit.
        verify (bool): Verify existing metadata/checksums instead of creating them.

    Raises:
        ValueError: Files, metadata, archive contents, or hashes are inconsistent.
        OSError: Release files cannot be read or written.
    """
    validate_tag(tag, tag.removeprefix("v"))
    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise ValueError("release source must be an exact commit SHA")
    archives = archive_names(tag)
    expected = archives | (
        {"release.json", "SHA256SUMS", "SHA256SUMS.minisig"} if verify else set()
    )
    if {p.name for p in directory.iterdir()} != expected:
        raise ValueError("release files do not match the complete target set")
    if any(p.is_symlink() or not p.is_file() for p in directory.iterdir()):
        raise ValueError("release files must be regular files")
    for name in sorted(archives):
        verify_archive(directory / name)
    metadata = {"tag": tag, "commit": commit, "targets": list(TARGETS)}
    metadata_path = directory / "release.json"
    if verify:
        if json.loads(metadata_path.read_text()) != metadata:
            raise ValueError(
                "release metadata does not match its tag and source commit"
            )
    else:
        metadata_path.write_text(json.dumps(metadata, indent=2) + "\n")
    checksums = []
    for name in sorted(archives | {"release.json"}):
        with (directory / name).open("rb") as data:
            digest = hashlib.file_digest(data, "sha256").hexdigest()
        checksums.append(f"{digest}  {name}\n")
    manifest = directory / "SHA256SUMS"
    if verify:
        if manifest.read_text() != "".join(checksums):
            raise ValueError("release checksums do not match the distributed files")
    else:
        manifest.write_text("".join(checksums))


def main() -> None:
    """Dispatch release tooling; invalid input terminates with a nonzero status."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["plan", "package", "manifest", "verify"])
    parser.add_argument("args", nargs="*")
    args = parser.parse_args()
    if args.command == "plan":
        event = os.environ.get("GITHUB_EVENT_NAME", "workflow_dispatch")
        if (
            event == "workflow_dispatch"
            and os.environ.get("GITHUB_REF", "refs/heads/main") != "refs/heads/main"
        ):
            raise ValueError("manual releases must run the workflow from main")
        tag, commit = plan(
            ROOT, os.environ.get("RELEASE_TAG", ""), event == "pull_request"
        )
        print(f"tag={tag}\ncommit={commit}")
    elif args.command == "package":
        (target,) = args.args
        print(package(ROOT, target))
    else:
        tag, commit, directory = args.args
        release_files(Path(directory), tag, commit, args.command == "verify")


if __name__ == "__main__":
    main()
