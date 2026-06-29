# Release checklist

Aegisguard publishes the PyPI distribution `aegisguard`. The Python import
package is `aegis`; the internal engine is `capguard`.

## One-time setup

Before the first tag, configure PyPI Trusted Publishing:

- PyPI project name: `aegisguard`
- GitHub owner / repository: `harsha-mangena/capguard`
- Workflow filename: `release.yml`
- GitHub environment: `pypi`

Create the matching GitHub environment named `pypi` and protect it with the
reviewers or branch/tag rules you want for production release authority.

## Preflight

1. Confirm `pyproject.toml` version matches `aegis/__init__.py`.
2. Confirm README says `pip install aegisguard`.
3. Confirm the release workflow uses Trusted Publishing with
   `id-token: write` only in the publish job and no password/token secret.
4. Run the local gate:

```bash
python -m pip install -e ".[dev,yaml]"
ruff check capguard tests examples
pytest -q
aegis bench
rm -rf dist build *.egg-info
python -m build
python -m twine check dist/*
```

5. Smoke install the wheel in a clean environment:

```bash
python -m venv /tmp/aegisguard-release-smoke
/tmp/aegisguard-release-smoke/bin/python -m pip install --upgrade pip
/tmp/aegisguard-release-smoke/bin/python -m pip install dist/*.whl
/tmp/aegisguard-release-smoke/bin/python - <<'PY'
import importlib.metadata as md
from aegis import Aegis, guard

assert md.version("aegisguard")
print(f"smoke ok {md.version('aegisguard')}")
PY
```

## Publish

Create and push an annotated version tag:

```bash
git tag -a v0.2.0 -m "aegisguard 0.2.0"
git push origin v0.2.0
```

The `release` workflow tests, builds, checks metadata, smoke-installs the wheel,
then publishes to PyPI via Trusted Publishing.

## Post-release

Verify the public package from a fresh environment:

```bash
python -m venv /tmp/aegisguard-pypi-verify
/tmp/aegisguard-pypi-verify/bin/python -m pip install --upgrade pip
/tmp/aegisguard-pypi-verify/bin/python -m pip install aegisguard
/tmp/aegisguard-pypi-verify/bin/python - <<'PY'
import importlib.metadata as md
from aegis import Aegis, guard

assert md.version("aegisguard")
print(f"verified {md.version('aegisguard')}")
PY
```
