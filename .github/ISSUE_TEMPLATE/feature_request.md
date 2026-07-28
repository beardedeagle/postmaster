---
name: Feature request
about: Suggest an improvement or new capability for postmaster
title: ""
labels: enhancement
assignees: ""
---

## Problem

What are you trying to do, and where does postmaster get in the way?

## Proposed solution

What you'd like to see. Describe the behavior you want — concrete examples
(CLI usage, exec.json snippets, key source configurations) are better than
vague labels.

## Alternatives considered

Other approaches you thought about, and why they fall short.

## Scope check

postmaster is focused on local, offline secret materialization — decrypt,
inject, execvp. Requests that fit a "minimal-trust, fail-closed, no
network" shape are the best fit. Requests that add network clients,
plugin systems, or remote secret-store integrations are out of scope.
