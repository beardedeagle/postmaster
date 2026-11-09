"""Check Nix feature configuration without installing Nix.

Run: python3 .github/actions/setup-nix/test.py [path-to-bash]
"""

import os
from pathlib import Path
import subprocess
import sys
import tempfile
import textwrap


action = (Path(__file__).resolve().parent / "action.yml").read_text()
section = action.split("    - name: Enable nix-command and flakes\n", 1)[1]
body = textwrap.dedent(section.split("      run: |\n", 1)[1])
bash = sys.argv[1] if len(sys.argv) > 1 else "/bin/bash"
cases = {
    "missing": None,
    "empty": "",
    "nix-command-only": "experimental-features = nix-command\n",
    "flakes-only": "experimental-features = flakes\n",
    "commented": "# experimental-features = nix-command flakes\n",
    "other-features": "experimental-features = ca-derivations\n",
    "enabled": "experimental-features = nix-command flakes\n",
    "no-newline": "experimental-features = nix-command",
}
for name, original in cases.items():
    with tempfile.TemporaryDirectory(prefix="postmaster-nix features-") as home:
        config = Path(home) / ".config/nix/nix.conf"
        if original is not None:
            config.parent.mkdir(parents=True)
            config.write_text(original)
        env = {**os.environ, "HOME": home}
        subprocess.run([bash, "-c", body], env=env, check=True)
        first = config.read_text()
        assert first.startswith(original or ""), f"{name}: existing config changed"
        features = set()
        for line in first.splitlines():
            key, separator, value = line.split("#", 1)[0].partition("=")
            if separator and key.strip() in ("experimental-features", "extra-experimental-features"):
                features.update(value.split())
        assert {"nix-command", "flakes"} <= features, f"{name}: missing features"
        subprocess.run([bash, "-c", body], env=env, check=True)
        assert config.read_text() == first, f"{name}: repeated setup changes config"

print(f"Nix feature setup: {len(cases)} cases pass")
