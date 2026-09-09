# Contributing to async-port-scanner

Thanks for your interest in contributing. This is a small, deliberately
simple TCP Connect port scanner — please discuss significant changes
(especially anything touching the scanning behavior itself) via an
issue before opening a PR, so scope stays aligned before any code is
written.

## Development setup

Development uses [uv](https://docs.astral.sh/uv/) and targets Python
3.12+ (CI runs 3.12, 3.13, and 3.14).

```bash
uv sync          # create the virtualenv and install dev dependencies
```

## The QA ladder

These four checks are enforced by CI on every push and pull request.
Run them locally before you push:

```bash
uv run ruff check           # lint
uv run ruff format --check  # formatting (drop --check to apply)
uv run mypy                 # type checking, strict
uv run pytest                # the full suite
```

## Project layout

```
src/async_port_scanner/
  cli.py       argument parsing and the console-script entry point
  core.py      AsyncTCPScanner, the TCP-connect scan engine
  output.py    the Output observer interface and OutputToScreen
tests/         pytest suite (local ephemeral-port fixtures, no
               external network calls)
```

## Scope

This project's whole pitch is being a *simple* scanner. Changes that
add new scan types, output formats, config files, or concurrency
limits are likely out of scope — open an issue first if you'd like to
propose one, rather than sending a PR directly.

## Changelog

This project keeps a [Keep a Changelog](https://keepachangelog.com/)
file. Add an entry under `## [Unreleased]` in
[`CHANGELOG.md`](CHANGELOG.md) describing user-facing changes.

## Pull requests

- Keep changes focused; don't widen a PR beyond what it needs.
- Commits and PRs describe the change and the reasoning; the diff shows
  the *what*, the message explains the *why*.
- Fork the repository, create a feature branch, and open a PR against
  `master` once the QA ladder above is green.

By contributing, you agree that your contributions are licensed under
the project's [AGPL-3.0-or-later license](LICENSE).
