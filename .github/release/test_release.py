"""Exercise release source authorization, archive integrity and real signatures."""

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

    def keypair(self, name):
        secret = self.root / f"{name}.key"
        public = self.root / f"{name}.pub"
        subprocess.run(
            ["minisign", "-G", "-W", "-s", str(secret), "-p", str(public)],
            check=True,
            capture_output=True,
        )
        return secret.read_text(), public.read_text().splitlines()[-1]

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
        (self.root / "SHA256SUMS.minisig").write_text("signature checked separately")
        release.release_files(self.root, self.tag, self.commit, True)
        with self.assertRaisesRegex(ValueError, "source commit"):
            release.release_files(self.root, self.tag, "b" * 40, True)
        self.archive(
            self.root / min(release.archive_names(self.tag)), binary=b"changed"
        )
        with self.assertRaisesRegex(ValueError, "checksums"):
            release.release_files(self.root, self.tag, self.commit, True)

    def test_real_signature_rejects_tampered_manifest_and_wrong_key(self):
        secret, public = self.keypair("release")
        _, other_public = self.keypair("other")
        manifest = self.root / "SHA256SUMS"
        manifest.write_text("original manifest\n")
        env = os.environ | {
            "MINISIGN_SECRET_KEY": secret,
            "MINISIGN_PUBLIC_KEY": public,
        }
        command = [
            "bash",
            str(release.ROOT / ".github/release/sign.sh"),
            self.tag,
            self.commit,
            str(self.root),
        ]
        subprocess.run(command, env=env, check=True, capture_output=True)
        verify = ["minisign", "-V", "-H", "-P", public, "-m", str(manifest)]
        self.assertEqual(
            subprocess.run(verify, check=False, capture_output=True).returncode, 0
        )
        manifest.write_text("tampered manifest\n")
        self.assertNotEqual(
            subprocess.run(verify, check=False, capture_output=True).returncode, 0
        )
        manifest.write_text("original manifest\n")
        verify[4] = other_public
        self.assertNotEqual(
            subprocess.run(verify, check=False, capture_output=True).returncode, 0
        )

    def test_signing_refuses_missing_configuration(self):
        env = os.environ.copy()
        env.pop("MINISIGN_SECRET_KEY", None)
        env.pop("MINISIGN_PUBLIC_KEY", None)
        command = [
            "bash",
            str(release.ROOT / ".github/release/sign.sh"),
            self.tag,
            self.commit,
            str(self.root),
        ]
        self.assertNotEqual(
            subprocess.run(
                command, env=env, check=False, capture_output=True
            ).returncode,
            0,
        )
        self.assertFalse((self.root / "SHA256SUMS.minisig").exists())

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
import os, sys
from pathlib import Path
name = Path(sys.argv[0]).name
if name == "install":
    Path("installed").touch()
sys.exit(1 if os.environ.get("REJECT") == name else 0)
""")
        program.chmod(0o755)
        for name in ["curl", "minisign", "shasum", "gh", "tar", "mkdir", "install"]:
            (tools / name).symlink_to(program)
        (self.root / "SHA256SUMS").write_text(
            "a" * 64 + "  postmaster-v0.1.0-aarch64-apple-darwin.tar.gz\n"
        )
        env = os.environ | {
            "PATH": str(tools) + os.pathsep + os.environ["PATH"],
            "POSTMASTER_RELEASE_PUBLIC_KEY": "fixture",
        }
        for failure in ["curl", "minisign", "shasum", "gh"]:
            with self.subTest(failure=failure):
                result = subprocess.run(
                    ["sh", "-c", snippet],
                    cwd=self.root,
                    env=env | {"REJECT": failure},
                    check=False,
                    capture_output=True,
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse((self.root / "installed").exists())
        subprocess.run(
            ["sh", "-c", snippet],
            cwd=self.root,
            env=env,
            check=True,
            capture_output=True,
        )
        self.assertTrue((self.root / "installed").exists())

    def test_complete_signed_release_and_manual_branch_guard(self):
        secret, public = self.keypair("release")
        directory = self.root / "dist"
        directory.mkdir()
        for name in release.archive_names(self.tag):
            self.archive(directory / name)
        release.release_files(directory, self.tag, self.commit, False)
        env = os.environ | {
            "MINISIGN_SECRET_KEY": secret,
            "MINISIGN_PUBLIC_KEY": public,
        }
        subprocess.run(
            [
                "bash",
                str(release.ROOT / ".github/release/sign.sh"),
                self.tag,
                self.commit,
                str(directory),
            ],
            env=env,
            check=True,
            capture_output=True,
        )
        release.release_files(directory, self.tag, self.commit, True)
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
        secret, public = self.keypair("release")
        directory = self.root / "dist"
        directory.mkdir()
        for name in release.archive_names(self.tag):
            self.archive(directory / name)
        release.release_files(directory, self.tag, self.commit, False)
        env = os.environ | {
            "MINISIGN_SECRET_KEY": secret,
            "MINISIGN_PUBLIC_KEY": public,
        }
        subprocess.run(
            [
                "bash",
                str(release.ROOT / ".github/release/sign.sh"),
                self.tag,
                self.commit,
                str(directory),
            ],
            env=env,
            check=True,
            capture_output=True,
        )
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
if args[:2] == ["attestation", "verify"] and os.environ.get("GH_TEST_BAD_ATTESTATION"):
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
            "MINISIGN_PUBLIC_KEY": public,
            "JUST_NO_DOTENV": "true",
        }
        command = [
            "bash",
            str(release.ROOT / ".github/release/publish.sh"),
            self.tag,
            self.commit,
            str(directory),
        ]
        for failure in [
            "GH_TEST_CORRUPT",
            "GH_TEST_EXISTING",
            "GH_TEST_BAD_ATTESTATION",
        ]:
            with self.subTest(failure=failure):
                log.write_text("")
                result = subprocess.run(
                    command,
                    cwd=release.ROOT,
                    env=env | {failure: "1"},
                    check=False,
                    capture_output=True,
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn('"edit"', log.read_text())
                if failure == "GH_TEST_EXISTING":
                    self.assertNotIn('"create"', log.read_text())
        log.write_text("")
        subprocess.run(
            command, cwd=release.ROOT, env=env, check=True, capture_output=True
        )
        calls = [json.loads(line) for line in log.read_text().splitlines()]
        self.assertEqual(calls[-1][:2], ["release", "edit"])
        self.assertIn("--draft=false", calls[-1])
        self.assertEqual(
            sum(call[:2] == ["attestation", "verify"] for call in calls), 8
        )


if __name__ == "__main__":
    unittest.main()
