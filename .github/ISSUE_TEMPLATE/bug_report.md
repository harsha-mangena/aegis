---
name: Bug report
about: Something doesn't work as documented
title: "[bug] "
labels: bug
---

**Not a security vulnerability?** If it is, please follow `SECURITY.md` instead
(private report), not a public issue.

**What happened**
A clear description of the bug.

**Minimal reproduction**
```python
# smallest snippet that shows the problem
```

**Expected vs actual**
What you expected, and what happened instead (include the exact error / decision).

**Environment**
- aegisguard version: `python -c "from aegis import Aegis; import importlib.metadata; print(importlib.metadata.version('aegisguard'))"`
- Python version / OS:
