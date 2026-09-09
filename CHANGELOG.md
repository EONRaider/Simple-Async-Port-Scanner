# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.0.0] - 2026-09-09

**First release on PyPI: `pip install async-port-scanner`.** This
release also fixes a crash on Python 3.11+ and is a breaking change —
see below.

### Fixed
- The scanner crashed with `TypeError` on Python 3.11, 3.12, and 3.13:
  `AsyncTCPScanner.execute()` called `asyncio.wait()` on a list of bare
  coroutines instead of `Task` objects, a pattern deprecated since
  Python 3.8 and rejected outright since 3.11. Replaced with
  `asyncio.run()` driving `asyncio.TaskGroup` throughout.
- `AsyncTCPScanner.__init__` called the deprecated
  `asyncio.get_event_loop()` outside a running loop; removed entirely
  now that `asyncio.run()` owns the event loop's lifecycle.
- A scan against a target that fails DNS resolution (or hits any
  `OSError` subclass other than `ConnectionRefusedError`) could raise
  an unhandled `KeyError` instead of being reported as a closed port
  with reason `Network error`.

### Changed
- **Distribution and invocation**: install `async-port-scanner` from
  PyPI (or run from source via `uv sync`), then run the
  `async-port-scanner` command — or `python -m async_port_scanner`.
  The old `python3 scanner/scanner.py ...` invocation is gone; there
  is no compatibility shim.
- **Import path**: `scanner.modules.core_scanner.AsyncTCPScanner` is
  now `async_port_scanner.AsyncTCPScanner` (also exported at the
  package top level, alongside `Output`/`OutputToScreen`).
- **Minimum Python version**: 3.12 (previously claimed 3.8+, though the
  bug above meant 3.11+ was already broken in practice).
- All four CLI options (`ADDRESSES`, `-p/--ports`, `--timeout`,
  `--open`) and the scan/output behavior are unchanged.

### Added
- `--version` flag.
- Full test suite (`pytest`), CI (lint/typecheck/test on every push and
  PR), and a release workflow that publishes to PyPI on a `v*` tag,
  gated on the same CI checks.

## [1.0.0] - 2022-07-10

Initial tagged release.
