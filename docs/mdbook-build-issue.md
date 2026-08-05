# mdbook build is broken: SUMMARY.md references a missing `changelog.md`

> **Status:** Pre-existing — not introduced by any recent documentation
> edits. It blocks `mdbook build docs`, so the rendered site under
> `docs/book/` is stale and cannot be regenerated until resolved.

## Summary

`docs/src/SUMMARY.md` declares a `Changelog` chapter pointing at
`./changelog.md`, which resolves to `docs/src/changelog.md` — a file that
does not exist. The project's changelog actually lives at the repository
root (`CHANGELOG.md`). mdbook fails fast on the missing chapter and emits
no rendered output.

## Reproduction

```console
$ mdbook build docs
ERROR failed to read chapter `./changelog.md`
	Caused by: No such file or directory (os error 2)
```

## Evidence

- `docs/src/SUMMARY.md:24` → `- [Changelog](./changelog.md)`
- `docs/src/changelog.md` → **missing** (`No such file or directory`)
- `CHANGELOG.md` (repo root) → present (~2.8 KB)
- `docs/book/` is `.gitignore`d (generated output), so this affects only
  local/CI rendering, not committed source.

## Impact

- `mdbook build docs` and `mdbook serve docs` fail; no rendered book is
  produced.
- Edits to the markdown source under `docs/src/` (e.g. `getting-started/`)
  do **not** propagate to the rendered HTML until this is fixed.
- The gitignored `docs/book/` is frozen at whatever was last successfully
  built.

## Fix options (in order of preference)

### 1. Include the root changelog via mdbook `{{#include}}` (recommended)

Create `docs/src/changelog.md` as a thin page that pulls in the root file,
keeping a single source of truth. `SUMMARY.md` stays as-is (`./changelog.md`
now exists):

```markdown
# Changelog

{{#include ../../CHANGELOG.md}}
```

mdbook resolves the include at build time; the root `CHANGELOG.md` remains
authoritative and there is no duplicated content to drift.

### 2. Repoint SUMMARY.md at the root file

Change `docs/src/SUMMARY.md:24` to:

```markdown
- [Changelog](../../CHANGELOG.md)
```

Caveat: verify mdbook accepts a chapter path outside `src/` (it generally
does, but worth confirming on your mdbook version).

### 3. Symlink

`docs/src/changelog.md` → `../../CHANGELOG.md`. Single source of truth, but
symlinks can be awkward across platforms/git checkouts, and mdbook's
handling of symlinked chapters should be confirmed.

### 4. Copy via a pre-build step

Have the `Justfile` copy `CHANGELOG.md` → `docs/src/changelog.md` before
`mdbook build`. Simple, but introduces a duplicate that can drift unless
the copy is automated and enforced.

## Recommendation

**Option 1 (`{{#include}}`)** — idiomatic mdbook, no duplication, root
`CHANGELOG.md` stays the single source of truth, and `SUMMARY.md` needs no
change.
