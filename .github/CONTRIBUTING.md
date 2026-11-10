# Contributing to postmaster

Postmaster decrypts local secret inputs, projects values into the application,
and replaces the launcher with the target binary through `execvp`.

External contributions are welcome.

By submitting a contribution you agree that it is licensed under the
project's [MIT license](../LICENSE) (inbound = outbound).

## Ground rules

- **Keep checks in the Justfile.** Git hooks and workflow definitions call
  the same recipes. Runner setup still needs separate verification, and a
  local pass doesn't establish that hosted CI ran. Don't add a CI check
  without a matching recipe.
- **Treat warnings as failures.** Clippy runs with `-D warnings`.
  Formatting and dependency license, source, and advisory checks must pass.
- **Test the behavior.** Add a regression that fails without the change.
  Match the crate's existing unit and integration tests.
- **This is a security tool.** Secret material, private keys, and
  decrypted values are core to its purpose. Changes to the decrypt path,
  key handling, or injection modes get extra scrutiny.

## Getting set up

You need Rust 1.99.1 or newer, [`just`](https://just.systems), and
[`lefthook`](https://lefthook.dev) for the git hooks.
`rust-toolchain.toml` selects the toolchain and required components through
`rustup`.

```sh
git clone git@github.com:beardedeagle/postmaster.git
cd postmaster
lefthook install     # wire up the pre-commit / pre-push hooks
just --list          # see every available recipe
```

## The development loop

Run the Rust gate before pushing. It includes native and release checks,
Linux-target Clippy, a locked build, and tests:

```sh
just ci-rust     # fmt-check, native/release/Linux clippy, build, test
just ci          # ci-rust + nix flake check
just docs        # mdBook build
```

GitHub workflows call the same recipes. The Docs workflow builds pull
requests and `main`, then uploads the book as a Pages artifact. Only pushes
and manual runs on `main` publish it through the `github-pages` environment.

For dependency policy checks:

```sh
just deny        # advisories, bans, licenses, sources
just audit       # advisory database check, warnings fail
```

## Submitting a change

1. Branch off `main` (`git switch -c fix/short-description`).
2. Make the change and add tests where needed.
3. Run the full `just ci`.
4. Open a PR. Use the PR template.
5. Include verification evidence and unresolved limits. Reviews focus on
   correctness, security, and consistency with the existing code.

## Reporting bugs and requesting features

Use the GitHub issue templates. For security issues, see
[Security policy](SECURITY.md) and report privately through advisories or the
contact in that file.
