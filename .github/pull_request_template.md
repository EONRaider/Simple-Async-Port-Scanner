<!--
  Thanks for contributing to async-port-scanner.

  Keep this short. A couple of dense paragraphs that explain what changed
  and why beats a long form with every box ticked. Delete any section that
  does not apply.
-->

## Summary

<!--
  What this changes, and why it is worth changing. If the diff is not
  obvious on its own, say what the behaviour was before and what it is
  after. For a bug fix, describe how it failed.
-->

## Related issues

<!-- e.g. Closes #12 — or "None" for standalone work. -->

## Verification

<!--
  How you know this works. Name the checks you ran locally and anything
  you exercised by hand (a real scan against a live or local target, a
  crafted port range or address list). "CI is green" alone is not
  verification for a behaviour change.
-->

- [ ] `uv run ruff check` and `uv run ruff format --check`
- [ ] `uv run mypy` (strict)
- [ ] `uv run pytest`

## Checklist

- [ ] Tests cover the new behaviour, including its failure paths.
- [ ] Dependency changes are locked — ran `uv lock` and committed `uv.lock`
      alongside the `pyproject.toml` edit.
- [ ] User-facing changes have a `CHANGELOG.md` entry under *Unreleased*.
- [ ] Docs updated if this changes the CLI, the output format, or the
      scan lifecycle (`README.md`, `ARCHITECTURE.md`).

<!--
  A core invariant worth keeping in mind: every per-port connection
  attempt is bounded by --timeout, and every failure mode (refused,
  timeout, DNS/network error) is classified into a result rather than
  raised -- a scan of bad targets degrades to slow, never to broken.
  If your change touches `_scan_target_port` or `parse_ports`, say in
  the PR how that invariant still holds.
-->
