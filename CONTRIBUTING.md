# Contributing

```bash
python -m venv .venv && . .venv/bin/activate     # Windows: .venv\Scripts\Activate.ps1
pip install -e ".[dev]" chdb                      # chdb: embedded ClickHouse for the tests
ruff check . && ruff format --check . && mypy
pytest --cov
```

- Keep the runtime dependency list empty unless there is a strong reason.
- New parsing code needs hostile-input tests (truncated, oversized, contradictory lengths).
- SQL belongs in `schema.sql` and `queries.py`; the Grafana panels live in
  `tools/build_dashboard.py` (run it to regenerate the JSON; a test checks they match). Every panel
  query is executed by the tests.
- Use documentation address ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24) in examples
  and tests, never real addresses or captures.
