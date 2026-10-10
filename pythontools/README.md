# pythontools/

Python side of hackbot. Go owns the core bot logic; Python is the escape hatch
for anything Go can't do cleanly, called through `exec.Command`:

```bash
hackbot py helpers.py slugify "Hello World"   # -> hello-world
```

Conventions:
- Each helper is a small module with a `main(argv)` and a stdout result.
- Keep helpers self-contained; no third-party imports unless a Go equivalent is
  impractical.
- Every helper has tests in `test_*.py`, run with pytest.