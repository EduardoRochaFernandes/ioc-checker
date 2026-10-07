# Contributing

This is a small learning project, but issues and pull requests are welcome.

```bash
git clone https://github.com/EduardoRochaFernandes/ioc-checker.git
cd ioc-checker
pip install -e ".[dev]"
ruff check .
pytest
```

- Tests must not make real HTTP calls (mock `requests.get`; see `tests/test_http_and_demo.py`).
- Never commit API keys, `.env` files, or real incident data.
