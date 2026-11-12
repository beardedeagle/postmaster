"""Exercise release source authorization, archive integrity and attestation policy."""

import io
import json
import os
import re
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
            pattern = call[call.index("--cert-identity-regex") + 1]
            for ref in ["refs/heads/main", "refs/tags/v0.1.0", "refs/tags/v0.1.0-rc.1"]:
                self.assertIsNotNone(re.fullmatch(pattern, identity + ref))
            for ref in [
                "refs/pull/15/merge",
                "refs/heads/untrusted",
                "refs/tags/untrusted",
                "refs/tags/v0.1.0/untrusted",
                "refs/heads/untrusted@refs/heads/main",
                "refs/tags/v0.1.0@refs/heads/main",
            ]:
                self.assertIsNone(re.fullmatch(pattern, identity + ref))
            self.assertIsNone(
                re.fullmatch(
                    pattern,
                    identity.replace("postmaster/", "other/") + "refs/heads/main",
                )
            )

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
            "GITHUB_REF": "refs/tags/" + self.tag,
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
        for ref, digest in [
            (env["GITHUB_REF"], self.commit),
            ("refs/heads/main", "b" * 40),
        ]:
            with self.subTest(ref=ref):
                log.write_text("")
                subprocess.run(
                    command,
                    cwd=release.ROOT,
                    env=env | {"GITHUB_REF": ref, "GITHUB_SHA": digest},
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
                    self.assertEqual(call[call.index("--source-ref") + 1], ref)
                    self.assertIn("--deny-self-hosted-runners", call)


if __name__ == "__main__":
    unittest.main()
