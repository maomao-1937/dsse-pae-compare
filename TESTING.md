# Testing

```sh
python -B -m unittest discover -s tests -v
python -B ci_checks.py
```

The tests exercise the published PAE vector, byte lengths for non-ASCII types, historical low-byte collisions for BMP and supplementary Unicode characters, base64 alphabet and padding equivalence, strict JSON, exact limits, file descriptor checks, private reports and quiet handling of unavailable stdout. The example runner checks exact JSON and exit codes. CI runs both commands on Ubuntu and Windows with Python 3.11.
