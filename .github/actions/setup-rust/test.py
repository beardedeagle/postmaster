"""Exercise Rust and Cargo tool setup without installing packages.

Run: python3 .github/actions/setup-rust/test.py [path-to-bash]
"""

import os
from pathlib import Path
import subprocess
import sys
import tempfile
import textwrap


action_dir = Path(__file__).resolve().parent
action = (action_dir / "action.yml").read_text()
bash = Path(sys.argv[1] if len(sys.argv) > 1 else "/bin/bash").resolve()
tools = {
    "just": ("Install just", "JUST_VERSION", "1.51.0"),
    "cargo-deny": ("Install cargo-deny", "CARGO_DENY_VERSION", "0.20.2"),
    "cargo-audit": ("Install cargo-audit", "CARGO_AUDIT_VERSION", "0.22.2"),
    "mdbook": ("Install mdbook", "MDBOOK_VERSION", "0.5.4"),
    "mdbook-mermaid": ("Install mdbook", "MDBOOK_MERMAID_VERSION", "0.17.0"),
}
scenarios = (
    "current", "outdated", "broken", "missing", "install-fails", "installed-wrong",
    "custom-root", "default-home",
)
failures = []
for tool, (step, version_var, version) in tools.items():
    section = action.split(f"    - name: {step}\n", 1)[1].split("\n    - name:", 1)[0]
    body = textwrap.dedent(section.split("      run: |\n", 1)[1])
    for scenario in scenarios:
        with tempfile.TemporaryDirectory(prefix="postmaster-setup-") as tmp:
            root = Path(tmp)
            home = root / "home"
            home.mkdir()
            cargo_home = root / "cargo home"
            install_root = root / "install root" if scenario == "custom-root" else (home / ".cargo" if scenario == "default-home" else cargo_home)
            bin_dir = install_root / "bin"
            bin_dir.mkdir(parents=True)
            shims = root / "shims"
            shims.mkdir()
            (shims / "bash").symlink_to(bash)
            log = root / "install.log"
            env = os.environ.copy()
            env.pop("CARGO_INSTALL_ROOT", None)
            env.update(
                HOME=str(home),
                PATH=f"{shims}:/usr/bin:/bin",
                CARGO_HOME=str(cargo_home),
                CARGO_INSTALL_TARGET_DIR=str(root / "build target"),
                GITHUB_ACTION_PATH=str(action_dir),
                GITHUB_PATH=str(root / "github-path"),
                TEST_TOOL=tool,
                TEST_VERSION=version,
                TEST_LOG=str(log),
                TEST_SCENARIO=scenario,
                TEST_INSTALL_ROOT=str(install_root),
            )
            if scenario == "default-home":
                env.pop("CARGO_HOME", None)
            if scenario == "custom-root":
                env["CARGO_INSTALL_ROOT"] = str(install_root)
            for name, (_, var, pinned) in tools.items():
                env[var] = pinned
                # The other mdBook executable remains available at its pin.
                executable = shims / name
                prefix = "v" if name == "mdbook" else ""
                reported = f"{name} {prefix}{pinned}"
                if name == tool:
                    if scenario == "missing":
                        continue
                    reported = f"{name} 0.0.0" if scenario != "current" else reported
                executable.write_text(
                    "#!/bin/sh\n"
                    + ("exit 127\n" if name == tool and scenario == "broken"
                       else f"printf '%s\\n' '{reported}'\n")
                )
                executable.chmod(0o755)
            cargo = shims / "cargo"
            cargo.write_text("""#!/bin/bash
set -eu
printf '%s\\n' "$@" > "$TEST_LOG"
[[ "$TEST_SCENARIO" != install-fails ]] || exit 1
mkdir -p "$TEST_INSTALL_ROOT/bin"
version="$TEST_VERSION"
[[ "$TEST_SCENARIO" != installed-wrong ]] || version=0.0.0
printf '#!/bin/sh\\nprintf "%%s\\n" "%s %s"\\n' "$TEST_TOOL" "$version" > "$TEST_INSTALL_ROOT/bin/$TEST_TOOL"
chmod +x "$TEST_INSTALL_ROOT/bin/$TEST_TOOL"
""")
            cargo.chmod(0o755)
            result = subprocess.run(
                [str(bash), "-c", body],
                env=env, capture_output=True, text=True,
            )
            try:
                should_fail = scenario in ("install-fails", "installed-wrong")
                assert (result.returncode != 0) == should_fail, result.stdout + result.stderr
                assert log.exists() == (scenario != "current"), "wrong install decision"
                if log.exists():
                    args = log.read_text().splitlines()
                    assert args[:2] == ["install", tool], args
                    assert args[args.index("--version") + 1] == version, args
                    assert "--locked" in args, args
                    assert args[args.index("--root") + 1] == str(install_root), args
                    assert args[args.index("--target-dir") + 1] == env["CARGO_INSTALL_TARGET_DIR"], args
                if not should_fail:
                    paths = Path(env["GITHUB_PATH"]).read_text().splitlines()
                    assert str(bin_dir) in paths, "verified install directory absent from PATH"
                    check = subprocess.run(
                        [tool, "--version"],
                        env={**env, "PATH": os.pathsep.join(paths + [env["PATH"]])},
                        capture_output=True, text=True,
                    )
                    assert check.returncode == 0, check.stderr
                    assert check.stdout.strip() in (f"{tool} {version}", f"{tool} v{version}")
            except (AssertionError, ValueError, FileNotFoundError) as error:
                failures.append(f"{tool}/{scenario}: {error}")

rust_scenarios = (
    "outdated", "current", "fresh", "targets", "update-fails", "show-fails",
    "target-fails", "missing",
)
section = action.split("    - name: Install pinned Rust toolchain\n", 1)[1].split("\n    - name:", 1)[0]
body = textwrap.dedent(section.split("      run: |\n", 1)[1])
for scenario in rust_scenarios:
    with tempfile.TemporaryDirectory(prefix="postmaster-rustup-") as tmp:
        root = Path(tmp)
        home = root / "home"
        home.mkdir()
        shims = root / "shims"
        shims.mkdir()
        log = root / "rustup.log"
        state = root / "version"
        if scenario != "fresh":
            state.write_text("1.99.1\n" if scenario == "current" else "1.98.0\n")
        targets = "aarch64-unknown-linux-gnu wasm32-unknown-unknown" if scenario in ("targets", "target-fails") else ""
        env = {
            **os.environ,
            "HOME": str(home),
            "PATH": str(shims),
            "GITHUB_PATH": str(root / "github-path"),
            "RUST_TARGETS": targets,
            "TEST_SCENARIO": scenario,
            "TEST_RUSTUP_LOG": str(log),
            "TEST_RUSTUP_STATE": str(state),
        }
        if scenario != "missing":
            rustup = shims / "rustup"
            rustup.write_text(r"""#!/bin/bash
set -eu
printf '%s\n' "$*" >> "$TEST_RUSTUP_LOG"
case "$1" in
    update)
        [[ "$*" == 'update stable --no-self-update' ]] || exit 2
        [[ "$TEST_SCENARIO" != update-fails ]] || exit 1
        printf '1.99.1\n' > "$TEST_RUSTUP_STATE"
        ;;
    show)
        [[ "$TEST_SCENARIO" != show-fails ]] || exit 1
        [[ -f "$TEST_RUSTUP_STATE" ]] || printf '1.99.1\n' > "$TEST_RUSTUP_STATE"
        ;;
    target)
        [[ "$TEST_SCENARIO" != target-fails ]] || exit 1
        ;;
    *) exit 2 ;;
esac
""")
            rustup.chmod(0o755)
        result = subprocess.run(
            [str(bash), "-c", body], env=env, capture_output=True, text=True,
            timeout=10,
        )
        try:
            should_fail = scenario in ("update-fails", "show-fails", "target-fails", "missing")
            assert (result.returncode != 0) == should_fail, result.stdout + result.stderr
            calls = log.read_text().splitlines() if log.exists() else []
            if not should_fail:
                assert state.read_text().strip() == "1.99.1", "stable remains below the required Rust version"
                assert "show" in calls, "repository components and targets were not resolved"
                if scenario == "outdated":
                    assert calls.index("update stable --no-self-update") < calls.index("show"), calls
                expected_targets = [f"target add {targets}"] if targets else []
                assert [call for call in calls if call.startswith("target ")] == expected_targets, calls
            elif scenario == "update-fails":
                assert calls == ["update stable --no-self-update"], calls
            elif scenario == "show-fails":
                assert calls[-1] == "show", calls
            elif scenario == "target-fails":
                assert calls[-1] == f"target add {targets}", calls
            else:
                assert not calls, calls
                assert "rustup must be preinstalled" in result.stderr, result.stderr
            if scenario != "missing":
                assert (root / "github-path").read_text().splitlines() == [str(home / ".cargo/bin")]
        except (AssertionError, ValueError, FileNotFoundError, IndexError) as error:
            failures.append(f"rustup/{scenario}: {error}")

if failures:
    raise SystemExit("\n".join(failures))
print(f"Cargo tool setup: {len(tools) * len(scenarios)} cases pass; Rust toolchain setup: {len(rust_scenarios)} cases pass")
