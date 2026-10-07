# Changelog

All notable changes to this project are documented here
(format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)).

## [Unreleased]

### Added
- `--demo` mode: offline run with synthetic canned API responses (no keys, no network).
- `pyproject.toml` packaging with an `ioc-checker` console command.
- HTTP-layer tests (mocked `requests`), verdict-boundary tests, demo-mode tests.
- GitHub Actions CI (ruff + pytest + demo smoke test), dev container, MIT `LICENSE`.
- `IOC_CHECKER_HOME` environment variable to choose where cache and log files are stored.

### Changed
- `requirements.txt` now lists runtime dependencies only (`pytest`/`ruff` moved to the `dev` extra).
- Console output is forced to UTF-8 so the report renders on legacy Windows consoles.

## [2.0.0]
- Initial release: IOC type detection, VirusTotal + AbuseIPDB lookups, verdicts, cache, audit log, bulk and JSON modes.
