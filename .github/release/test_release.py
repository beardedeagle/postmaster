"""Exercise release source authorization, archive integrity and attestation policy."""

import io
import json
import os
import subprocess
import tarfile
import tempfile
import unittest
from pathlib import Path

import release


class ReleaseTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="postmaster-release-test-")
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.tag = "v0.1.0"
        self.commit = "a" * 40

    def init_source(self):
        release.git(self.root, "init", "-b", "main")
        (self.root / "Cargo.toml").write_text('[package]\nversion = "0.1.0"\n')
        release.git(self.root, "add", "Cargo.toml")
        release.git(
            self.root,
            "-c",
            "commit.gpgsign=false",
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "user.name=Release test",
            "-c",
            "user.email=release@example.invalid",
            "commit",
            "-m",
            "fixture",
        )
        release.git(self.root, "tag", self.tag)
        release.git(self.root, "update-ref", "refs/remotes/origin/main", "HEAD")
        return release.git(self.root, "rev-parse", "HEAD")

    def archive(self, path, binary=b"binary", name="postmaster", kind=tarfile.REGTYPE):
        with tarfile.open(path, "w:gz") as archive:
            for entry, data, mode in [
                (name, binary, 0o755),
                ("LICENSE", b"license", 0o644),
            ]:
                info = tarfile.TarInfo(entry)
                info.mode = mode
                info.type = kind if entry == name else tarfile.REGTYPE
                info.size = len(data) if info.isfile() else 0
                archive.addfile(info, io.BytesIO(data) if info.isfile() else None)

    def files(self):
        for name in release.archive_names(self.tag):
            self.archive(self.root / name)

    def test_tag_resolves_its_own_manifest_and_rejects_unmerged_commit(self):
        release.git(self.root, "init", "-b", "main")
        manifest = self.root / "Cargo.toml"
        manifest.write_text('[package]\nversion = "0.1.0"\n')
        release.git(self.root, "add", "Cargo.toml")
        commit_args = [
            "-c",
            "commit.gpgsign=false",
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "user.name=Release test",
            "-c",
            "user.email=release@example.invalid",
            "commit",
            "-m",
            "fixture",
        ]
        release.git(self.root, *commit_args)
        release.git(self.root, "tag", self.tag)
        original = release.git(self.root, "rev-parse", "HEAD")
        manifest.write_text('[package]\nversion = "0.2.0"\n')
        release.git(self.root, "add", "Cargo.toml")
        release.git(self.root, *commit_args)
        release.git(self.root, "update-ref", "refs/remotes/origin/main", "HEAD")
        self.assertEqual(release.plan(self.root, self.tag, False), (self.tag, original))
        release.git(self.root, "checkout", "-b", "unmerged")
        manifest.write_text('[package]\nversion = "0.3.0"\n')
        release.git(self.root, "add", "Cargo.toml")
        release.git(self.root, *commit_args)
        release.git(self.root, "tag", "v0.3.0")
        with self.assertRaisesRegex(ValueError, "reachable from main"):
            release.plan(self.root, "v0.3.0", False)
        release.git(self.root, "tag", "v0.9.0", original)
        with self.assertRaisesRegex(ValueError, "Cargo.toml"):
            release.plan(self.root, "v0.9.0", False)

    def test_tag_rejects_revision_syntax_and_shell_input(self):
        for tag in ["main", "v0.1.0^{commit}", "v0.1.0;exit", "v0.1.0\n", "v../0.1.0"]:
            with self.subTest(tag=tag), self.assertRaises(ValueError):
                release.validate_tag(tag, "0.1.0")

    def test_archive_rejects_traversal_links_and_duplicate_entries(self):
        for name, kind in [
            ("../postmaster", tarfile.REGTYPE),
            ("postmaster", tarfile.SYMTYPE),
            ("LICENSE", tarfile.REGTYPE),
        ]:
            path = self.root / "bad.tar.gz"
            self.archive(path, name=name, kind=kind)
            with self.subTest(name=name, kind=kind), self.assertRaises(ValueError):
                release.verify_archive(path)

    def test_manifest_rejects_missing_and_unexpected_targets(self):
        self.files()
        extra = self.root / "unexpected.tar.gz"
        extra.write_bytes(b"unexpected")
        with self.assertRaisesRegex(ValueError, "complete target set"):
            release.release_files(self.root, self.tag, self.commit, False)
        extra.unlink()
        (self.root / next(iter(release.archive_names(self.tag)))).unlink()
        with self.assertRaisesRegex(ValueError, "complete target set"):
            release.release_files(self.root, self.tag, self.commit, False)

    def test_manifest_binds_source_and_rejects_changed_archive(self):
        self.files()
        release.release_files(self.root, self.tag, self.commit, False)
        release.release_files(self.root, self.tag, self.commit, True)
        with self.assertRaisesRegex(ValueError, "source commit"):
            release.release_files(self.root, self.tag, "b" * 40, True)
        self.archive(
            self.root / min(release.archive_names(self.tag)), binary=b"changed"
        )
        with self.assertRaisesRegex(ValueError, "checksums"):
            release.release_files(self.root, self.tag, self.commit, True)

    def test_install_instructions_stop_on_failed_verification(self):
        guide = (release.ROOT / "docs/src/development/releases.md").read_text()
        snippet = (
            guide.split("## Verify and install", 1)[1]
            .split("```sh\n", 1)[1]
            .split("```", 1)[0]
        )
        tools = self.root / "bin"
        tools.mkdir()
        program = tools / "stub"
        program.write_text("""#!/usr/bin/env python3
import json, os, sys
from pathlib import Path
name = Path(sys.argv[0]).name
if name == "install":
    Path("installed").touch()
if name == "gh":
    with Path("verified.jsonl").open("a") as log:
        log.write(json.dumps(sys.argv[1:]) + "\\n")
    if os.environ.get("REJECT_ARTIFACT") == sys.argv[3]:
        sys.exit(1)
sys.exit(1 if os.environ.get("REJECT") == name else 0)
""")
        program.chmod(0o755)
        for name in ["curl", "shasum", "gh", "tar", "mkdir", "install"]:
            (tools / name).symlink_to(program)
        archive = "postmaster-v0.1.0-aarch64-apple-darwin.tar.gz"
        (self.root / "SHA256SUMS").write_text("a" * 64 + f"  {archive}\n")
        env = os.environ | {
            "PATH": str(tools) + os.pathsep + os.environ["PATH"],
        }
        for failure in [
            {"REJECT": "curl"},
            {"REJECT": "shasum"},
            {"REJECT_ARTIFACT": "SHA256SUMS"},
            {"REJECT_ARTIFACT": archive},
        ]:
            with self.subTest(failure=failure):
                result = subprocess.run(
                    ["sh", "-c", snippet],
                    cwd=self.root,
                    env=env | failure,
                    check=False,
                    capture_output=True,
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse((self.root / "installed").exists())
        log = self.root / "verified.jsonl"
        log.write_text("")
        subprocess.run(
            ["sh", "-c", snippet],
            cwd=self.root,
            env=env,
            check=True,
            capture_output=True,
        )
        self.assertTrue((self.root / "installed").exists())
        calls = [json.loads(line) for line in log.read_text().splitlines()]
        self.assertEqual(
            [call[:3] for call in calls],
            [
                ["attestation", "verify", "SHA256SUMS"],
                ["attestation", "verify", archive],
            ],
        )
        identity = (
            "https://github.com/beardedeagle/postmaster/.github/workflows/release.yml@"
        )
        for call in calls:
            self.assertEqual(call[call.index("--repo") + 1], "beardedeagle/postmaster")
            self.assertEqual(
                call[call.index("--signer-workflow") + 1],
                "beardedeagle/postmaster/.github/workflows/release.yml",
            )
            self.assertIn("--deny-self-hosted-runners", call)
            certificate = call[call.index("--cert-identity") + 1]
            self.assertEqual(certificate, identity + "refs/heads/main")
            for ref in [
                "refs/tags/v0.1.0",
                "refs/tags/v0.1.0-rc.1",
                "refs/pull/15/merge",
                "refs/heads/untrusted",
                "refs/tags/untrusted",
                "refs/tags/v0.1.0/untrusted",
                "refs/heads/untrusted@refs/heads/main",
                "refs/tags/v0.1.0@refs/heads/main",
            ]:
                self.assertNotEqual(certificate, identity + ref)
            self.assertNotEqual(
                certificate,
                identity.replace("postmaster/", "other/") + "refs/heads/main",
            )

    def test_workflow_request_requires_main_source_and_matching_run(self):
        commit = self.init_source()
        event = self.root / "event.json"
        request = self.root / "request.json"
        run = {
            "event": "push",
            "conclusion": "success",
            "head_sha": commit,
            "head_repository": {"full_name": "beardedeagle/postmaster"},
        }
        event.write_text(json.dumps({"workflow_run": run}))
        request.write_text(json.dumps({"tag": self.tag, "commit": commit}))
        env = {
            "GITHUB_EVENT_NAME": "workflow_run",
            "GITHUB_REF": "refs/heads/main",
            "GITHUB_REPOSITORY": "beardedeagle/postmaster",
            "GITHUB_EVENT_PATH": str(event),
            "RELEASE_REQUEST": str(request),
        }
        self.assertEqual(release.release_plan(self.root, env), (self.tag, commit))
        recheck = env | {"RELEASE_TAG": self.tag}
        del recheck["RELEASE_REQUEST"]
        self.assertEqual(release.release_plan(self.root, recheck), (self.tag, commit))
        for change in [
            {"event": "pull_request"},
            {"conclusion": "failure"},
            {"head_repository": {"full_name": "other/postmaster"}},
            {"head_repository": {"full_name": None}},
            {"head_sha": "invalid"},
        ]:
            with self.subTest(change=change), self.assertRaises(ValueError):
                event.write_text(json.dumps({"workflow_run": run | change}))
                release.release_plan(self.root, env)
        for raw in [
            b"x" * 4097,
            b"{",
            b"[]",
            b'"request"',
            b'{"tag":"v0.1.0","tag":"v0.2.0","commit":"' + commit.encode() + b'"}',
            json.dumps({"tag": self.tag, "commit": commit, "extra": 1}).encode(),
            json.dumps({"tag": None, "commit": commit}).encode(),
            json.dumps({"tag": self.tag, "commit": "invalid"}).encode(),
            json.dumps({"tag": "v0.1.0;exit", "commit": commit}).encode(),
        ]:
            with self.subTest(raw=raw[:80]), self.assertRaises(ValueError):
                request.write_bytes(raw)
                release.read_request(request)
        alias = self.root / "alias.json"
        alias.symlink_to(request)
        with self.assertRaises(OSError):
            release.read_request(alias)
        fifo = self.root / "request-fifo"
        os.mkfifo(fifo)
        with self.assertRaisesRegex(ValueError, "regular file"):
            release.read_request(fifo)

    def test_annotated_requests_resolve_to_the_same_commit_and_reject_other_sources(
        self,
    ):
        commit = self.init_source()
        release.git(self.root, "tag", "-d", self.tag)
        release.git(
            self.root,
            "-c",
            "user.name=Release test",
            "-c",
            "user.email=release@example.invalid",
            "tag",
            "-a",
            self.tag,
            "-m",
            "annotated fixture",
        )
        annotated = release.git(self.root, "rev-parse", f"refs/tags/{self.tag}")
        event = self.root / "event.json"
        request = self.root / "request.json"
        run = {
            "event": "push",
            "conclusion": "success",
            "head_repository": {"full_name": "beardedeagle/postmaster"},
        }
        env = {
            "GITHUB_EVENT_NAME": "workflow_run",
            "GITHUB_REF": "refs/heads/main",
            "GITHUB_REPOSITORY": "beardedeagle/postmaster",
            "GITHUB_EVENT_PATH": str(event),
            "RELEASE_REQUEST": str(request),
        }
        for head_sha, request_sha in [
            (commit, commit),
            (commit, annotated),
            (annotated, commit),
            (annotated, annotated),
        ]:
            with self.subTest(head_sha=head_sha, request_sha=request_sha):
                event.write_text(
                    json.dumps({"workflow_run": run | {"head_sha": head_sha}})
                )
                request.write_text(json.dumps({"tag": self.tag, "commit": request_sha}))
                self.assertEqual(
                    release.release_plan(self.root, env), (self.tag, commit)
                )
        release.git(
            self.root,
            "-c",
            "commit.gpgsign=false",
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "user.name=Release test",
            "-c",
            "user.email=release@example.invalid",
            "commit",
            "--allow-empty",
            "-m",
            "different source",
        )
        other = release.git(self.root, "rev-parse", "HEAD")
        event.write_text(json.dumps({"workflow_run": run | {"head_sha": commit}}))
        request.write_text(json.dumps({"tag": self.tag, "commit": other}))
        with self.assertRaisesRegex(ValueError, "differs from the triggering workflow"):
            release.release_plan(self.root, env)
        event.write_text(json.dumps({"workflow_run": run | {"head_sha": other}}))
        with self.assertRaisesRegex(ValueError, "tag differs"):
            release.release_plan(self.root, env)

    def test_request_cannot_release_an_unmerged_tag_or_use_tag_workflow_identity(self):
        self.init_source()
        release.git(self.root, "checkout", "-b", "unmerged")
        (self.root / "Cargo.toml").write_text('[package]\nversion = "0.2.0"\n')
        release.git(self.root, "add", "Cargo.toml")
        release.git(
            self.root,
            "-c",
            "commit.gpgsign=false",
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "user.name=Release test",
            "-c",
            "user.email=release@example.invalid",
            "commit",
            "-m",
            "unmerged",
        )
        release.git(self.root, "tag", "v0.2.0")
        commit = release.git(self.root, "rev-parse", "HEAD")
        event = self.root / "event.json"
        event.write_text(
            json.dumps(
                {
                    "workflow_run": {
                        "event": "push",
                        "conclusion": "success",
                        "head_sha": commit,
                        "head_repository": {"full_name": "beardedeagle/postmaster"},
                    }
                }
            )
        )
        request = self.root / "request.json"
        request.write_text(json.dumps({"tag": "v0.2.0", "commit": commit}))
        env = {
            "GITHUB_EVENT_NAME": "workflow_run",
            "GITHUB_REF": "refs/heads/main",
            "GITHUB_REPOSITORY": "beardedeagle/postmaster",
            "GITHUB_EVENT_PATH": str(event),
            "RELEASE_REQUEST": str(request),
        }
        with self.assertRaisesRegex(ValueError, "reachable from main"):
            release.release_plan(self.root, env)
        for trigger in ["push", "workflow_run", "workflow_dispatch"]:
            with (
                self.subTest(trigger=trigger),
                self.assertRaisesRegex(ValueError, "workflow from main"),
            ):
                release.release_plan(
                    self.root,
                    env
                    | {
                        "GITHUB_EVENT_NAME": trigger,
                        "GITHUB_REF": "refs/tags/v0.2.0",
                    },
                )
        self.assertEqual(
            release.release_plan(self.root, {"GITHUB_EVENT_NAME": "pull_request"}),
            ("v0.2.0", commit),
        )

    def test_main_tooling_builds_and_packages_source_without_running_its_justfile(self):
        self.init_source()
        (self.root / "LICENSE").write_text("fixture license")
        (self.root / "Justfile").write_text(
            "release-build target:\n    touch forbidden\n    exit 77\n"
        )
        tools = self.root / "bin"
        tools.mkdir()
        cargo = tools / "cargo"
        cargo.write_text("""#!/usr/bin/env python3
import json, os, sys
from pathlib import Path
args = sys.argv[1:]
root = Path(os.environ["BUILD_TEST_ROOT"])
with (root / "cargo.jsonl").open("a") as log:
    log.write(json.dumps(args) + "\\n")
if "build" in args:
    binary = root / "target" / args[args.index("--target") + 1] / "release/postmaster"
    binary.parent.mkdir(parents=True)
    binary.write_text('#!/bin/sh\\nif [ "$1" = --version ]; then echo "postmaster 0.1.0"; fi\\n')
    binary.chmod(0o755)
""")
        cargo.chmod(0o755)
        subprocess.run(
            ["just", "release-build", release.TARGETS[0], str(self.root)],
            cwd=release.ROOT,
            env=os.environ
            | {
                "BUILD_TEST_ROOT": str(self.root),
                "PATH": str(tools) + os.pathsep + os.environ["PATH"],
                "JUST_NO_DOTENV": "true",
            },
            check=True,
            capture_output=True,
        )
        self.assertFalse((release.ROOT / "forbidden").exists())
        self.assertFalse((self.root / "forbidden").exists())
        calls = [
            json.loads(line)
            for line in (self.root / "cargo.jsonl").read_text().splitlines()
        ]
        self.assertEqual([call[1] for call in calls], ["test", "build"])
        for call in calls:
            self.assertEqual(
                call[call.index("--manifest-path") + 1], str(self.root / "Cargo.toml")
            )
        archive = (
            self.root
            / "target/release-artifacts"
            / f"postmaster-{self.tag}-{release.TARGETS[0]}.tar.gz"
        )
        with tarfile.open(archive) as package:
            self.assertEqual(package.extractfile("LICENSE").read(), b"fixture license")

    def test_manual_release_rejects_untrusted_branch(self):
        env = os.environ | {
            "GITHUB_EVENT_NAME": "workflow_dispatch",
            "GITHUB_REF": "refs/heads/untrusted",
            "RELEASE_TAG": self.tag,
        }
        result = subprocess.run(
            ["python3", str(release.ROOT / ".github/release/release.py"), "plan"],
            env=env,
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("workflow from main", result.stderr)

    def test_publication_requires_verified_downloads_and_preserves_existing_release(
        self,
    ):
        directory = self.root / "dist"
        directory.mkdir()
        for name in release.archive_names(self.tag):
            self.archive(directory / name)
        release.release_files(directory, self.tag, self.commit, False)
        tools = self.root / "bin"
        tools.mkdir()
        fake = tools / "gh"
        fake.write_text("""#!/usr/bin/env python3
import json, os, shutil, sys
from pathlib import Path
args = sys.argv[1:]
with Path(os.environ["GH_TEST_LOG"]).open("a") as log:
    log.write(json.dumps(args) + "\\n")
if args[:2] == ["release", "view"]:
    sys.exit(0 if os.environ.get("GH_TEST_EXISTING") else 1)
if args[:2] == ["release", "download"]:
    target = Path(args[args.index("--dir") + 1])
    for source in Path(os.environ["GH_TEST_ASSETS"]).iterdir():
        shutil.copyfile(source, target / source.name)
    if os.environ.get("GH_TEST_CORRUPT"):
        (target / "release.json").write_text("{}")
    if os.environ.get("GH_TEST_MISSING"):
        (target / os.environ["GH_TEST_MISSING"]).unlink()
if args[:2] == ["attestation", "verify"] and Path(args[2]).name == os.environ.get("GH_TEST_BAD_ATTESTATION"):
    sys.exit(1)
""")
        fake.chmod(0o755)
        log = self.root / "gh.log"
        env = os.environ | {
            "PATH": str(tools) + os.pathsep + os.environ["PATH"],
            "GH_TEST_LOG": str(log),
            "GH_TEST_ASSETS": str(directory),
            "GITHUB_REPOSITORY": "beardedeagle/postmaster",
            "GITHUB_SHA": self.commit,
            "GITHUB_REF": "refs/heads/main",
            "JUST_NO_DOTENV": "true",
        }
        command = [
            "bash",
            str(release.ROOT / ".github/release/publish.sh"),
            self.tag,
            self.commit,
            str(directory),
        ]
        files = release.archive_names(self.tag) | {"SHA256SUMS", "release.json"}
        for failure in [
            {"GH_TEST_CORRUPT": "1"},
            {"GH_TEST_EXISTING": "1"},
            {"GH_TEST_MISSING": min(files)},
            *({"GH_TEST_BAD_ATTESTATION": name} for name in sorted(files)),
        ]:
            with self.subTest(failure=failure):
                log.write_text("")
                result = subprocess.run(
                    command,
                    cwd=release.ROOT,
                    env=env | failure,
                    check=False,
                    capture_output=True,
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn('"edit"', log.read_text())
                if "GH_TEST_EXISTING" in failure:
                    self.assertNotIn('"create"', log.read_text())
        for ref in ["refs/tags/" + self.tag, "refs/heads/untrusted"]:
            log.write_text("")
            result = subprocess.run(
                command,
                cwd=release.ROOT,
                env=env | {"GITHUB_REF": ref},
                check=False,
                capture_output=True,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(log.read_text(), "")
        for digest in [self.commit, "b" * 40]:
            with self.subTest(digest=digest):
                log.write_text("")
                subprocess.run(
                    command,
                    cwd=release.ROOT,
                    env=env | {"GITHUB_SHA": digest},
                    check=True,
                    capture_output=True,
                )
                calls = [json.loads(line) for line in log.read_text().splitlines()]
                self.assertEqual(calls[-1][:2], ["release", "edit"])
                self.assertIn("--draft=false", calls[-1])
                verified = [
                    call for call in calls if call[:2] == ["attestation", "verify"]
                ]
                self.assertEqual({Path(call[2]).name for call in verified}, files)
                self.assertEqual(len(verified), len(files))
                for call in verified:
                    self.assertEqual(
                        call[call.index("--repo") + 1], "beardedeagle/postmaster"
                    )
                    self.assertEqual(
                        call[call.index("--signer-workflow") + 1],
                        "beardedeagle/postmaster/.github/workflows/release.yml",
                    )
                    self.assertEqual(call[call.index("--source-digest") + 1], digest)
                    self.assertEqual(
                        call[call.index("--source-ref") + 1], "refs/heads/main"
                    )
                    self.assertEqual(
                        call[call.index("--cert-identity") + 1],
                        "https://github.com/beardedeagle/postmaster/.github/workflows/release.yml@refs/heads/main",
                    )
                    self.assertIn("--deny-self-hosted-runners", call)


if __name__ == "__main__":
    unittest.main()
