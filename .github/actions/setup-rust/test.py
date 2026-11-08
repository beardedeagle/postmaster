"""Exercise optional tool setup without installing packages.

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
    "cargo-deny": ("Install cargo-deny", "CARGO_DENY_VERSION", "0.20.2"),
    "cargo-audit": ("Install cargo-audit", "CARGO_AUDIT_VERSION", "0.22.2"),
    "mdbook": ("Install mdbook", "MDBOOK_VERSION", "0.5.4"),
    "mdbook-mermaid": ("Install mdbook", "MDBOOK_MERMAID_VERSION", "0.17.0"),
}
scenarios = (
    "current", "outdated", "broken", "missing", "install-fails", "installed-wrong",
    "custom-root",
)
failures = []
for tool, (step, version_var, version) in tools.items():
    section = action.split(f"    - name: {step}\n", 1)[1].split("\n    - name:", 1)[0]
    body = textwrap.dedent(section.split("      run: |\n", 1)[1])
    for scenario in scenarios:
        with tempfile.TemporaryDirectory(prefix="postmaster-setup-") as tmp:
            root = Path(tmp)
            cargo_home = root / "cargo home"
            install_root = root / "install root" if scenario == "custom-root" else cargo_home
            bin_dir = install_root / "bin"
            bin_dir.mkdir(parents=True)
            shims = root / "shims"
            shims.mkdir()
            (shims / "bash").symlink_to(bash)
            log = root / "install.log"
            env = os.environ.copy()
            env.pop("CARGO_INSTALL_ROOT", None)
            env.update(
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

if failures:
    raise SystemExit("\n".join(failures))
print(f"Optional tool setup: {len(tools) * len(scenarios)} cases pass")
