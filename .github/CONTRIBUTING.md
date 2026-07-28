# Contributing to postmaster

postmaster is a standalone, format-neutral local secret materialization
engine. It decrypts encrypted secret inputs at process launch time and
injects them into a child process via environment variables, files, or
systemd credentials — then `execvp`s the target binary directly.

External contributions are welcome.

By submitting a contribution you agree that it is licensed under the
project's [MIT license](../LICENSE) (inbound = outbound).

## Ground rules

- **The Justfile is the single source of truth.** The local git hooks
  (lefthook) and CI both call the same `just` recipes, so what passes
  locally passes in CI. Don't add a check to CI that isn't a `just` recipe.
- **The bar is enforced, not aspirational.** Clippy runs with `-D
  warnings`, formatting is checked, and the dependency license/source
  policy is gated. CI will not go green on a warning.
- **Real tests, not coverage theater.** New behavior needs a test that
  would fail without the change. Match the existing unit/integration
  style in the crate.
- **This is a security tool.** Secret material, private keys, and
  decrypted values are core to its purpose. Changes to the decrypt path,
  key handling, or injection modes get extra scrutiny.

## Getting set up

You need a recent stable Rust toolchain (`rustup` + the
`rust-toolchain.toml` will help), [`just`](https://just.systems), and
[`lefthook`](https://lefthook.dev) for the git hooks.

```sh
git clone git@github.com:beardedeagle/postmaster.git
cd postmaster
lefthook install     # wire up the pre-commit / pre-push hooks
just --list          # see every available recipe
```

## The development loop

Run the full native gate before you push — it is exactly what CI runs:

```sh
just ci-rust     # fmt-check, clippy, build, test
just ci          # ci-rust + nix flake check
just docs        # mdBook build
```

For dependency policy checks:

```sh
just deny        # cargo deny check (advisories, bans, sources)
```

## Submitting a change

1. Branch off `main` (`git switch -c fix/short-description`).
2. Make your change + add tests where appropriate.
3. Run the full `just ci`.
4. Open a PR. Use the PR template.
5. Be patient — reviews will focus on correctness, security posture, and
   consistency with the existing style.

## Reporting bugs and requesting features

Please use the GitHub issue templates. For security issues, see
`SECURITY.md` and report privately (GitHub Security Advisories or the
contact in that file).
