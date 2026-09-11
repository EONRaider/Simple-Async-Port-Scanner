# Security Policy

## Supported Versions

Only the latest released version of async-port-scanner receives
security fixes. Older versions are not backported.

## Reporting a Vulnerability

Please report security vulnerabilities privately rather than opening
a public issue.

- Preferred: use GitHub's [private vulnerability
  reporting](https://github.com/EONRaider/Simple-Async-Port-Scanner/security/advisories/new)
  for this repository.
- Alternative: email livewire_voodoo@protonmail.com with a description
  of the vulnerability, the affected version, and steps to reproduce
  it.

You should expect an initial response within 5 business days. We aim
to confirm the vulnerability, assess its severity, and agree on a
disclosure timeline with you within that window.

We follow coordinated disclosure: once a fix is available, we will
credit reporters (unless anonymity is requested) in the release notes
and CHANGELOG.md. We ask that you not publicly disclose the
vulnerability until a fixed version has been released, and in any case
not before 90 days have elapsed since your initial report, whichever
comes first.

## Scope

async-port-scanner is a TCP Connect port scanner. Of particular
interest are:

- Crashes, hangs, or excessive resource consumption when parsing
  untrusted or adversarial CLI input — malformed port numbers, port
  ranges, or address lists passed to `parse_ports` / `process_cli_args`.
- Any deviation from documented behavior that could mislead a caller
  about the actual state of a scanned port.

This application intentionally spawns one worker per target-port
combination with no maximum-concurrency cap, which can produce
traffic resembling a SYN-flood against hosts that can't absorb the
burst. That is a **known, already-documented design tradeoff** — see
the ADVISORY in [README.md](README.md#application-performance) — and
not something to report here as a new finding.

Vulnerabilities in third-party tooling used only in CI (linters, type
checkers, the build backend) are out of scope for this policy —
please report those upstream instead.
