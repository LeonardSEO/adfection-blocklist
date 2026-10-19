# Contributing

## Missing indicators

Open an issue or pull request with the exact hostname, a public primary-source URL, the publication/observation date and the host's reported role. Add the entry to the appropriate source file using:

```text
host.example.org  # discover-tech: source section and reason
```

Valid categories are `candiru`, `discover-tech`, `bindecy` and `intelos`. Keep the source URL in a nearby comment. For discovered candidates, record why the evidence supports inclusion in `candidates/approved.txt`; a certificate or shared IP alone is insufficient. Never include credentials or private victim data.

Do not edit generated files directly. After updating sources, rebuild and verify:

```bash
python3 -m unittest discover -s tests -v
python3 scripts/build.py
python3 scripts/build.py --check
```

Commit source changes together with regenerated lists and the README table. Update the source coverage notes and changelog when counts or policy change. Maintainers review evidence before merging; discovery results are never approved by automation.

## False positives

Include the exact domain, the affected list and format, what stopped working, and evidence of legitimate use or changed ownership. Try a local exception first to establish the cause. Public issues should not contain private logs or personal information.

## Code changes

Use Python 3.10+ and the standard library. Add focused regression tests for parsing, exclusion, DNS matching, generated formats or discovery behavior affected by a change. Network services are mocked in tests so CI does not rely on API access. External API limits or failures must remain visible; they must not be reported as proof that no infrastructure exists.
