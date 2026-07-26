---
name: Managed artifact builds
description: Environment requirements for building artifact packages outside their managed workflows.
---

Artifact Vite builds are configured to fail fast unless both `PORT` and `BASE_PATH` are provided. Managed artifact workflows inject these values automatically; standalone validation commands must provide the same environment explicitly.

**Why:** The imported workspace's artifact services run correctly through their managed workflows, while a plain root build initially failed before reaching application compilation because those variables were absent.

**How to apply:** Prefer validating artifact services through their managed workflows. If running a package build directly, set the package's assigned `PORT` and preview `BASE_PATH` first.