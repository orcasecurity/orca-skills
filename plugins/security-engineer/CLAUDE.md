# Testing

Every new function or behaviour must have unit tests. Use table-driven tests: define a `CASES` list of `(description, input, expected)` tuples and loop with `self.subTest(description)`.

Run: `python3 skills/run/tests/test_orchestrator.py`
