# Straw Python protocol bindings

The `straw-protos` distribution provides generated bindings under `straw_protos` plus equivalent
registration-signing helpers.

```python
from straw_protos.straw.v1 import straw_pb2
```

Every release matches the same immutable `straw-protos` tag and records exact provenance. Install from an exact public
Git tag; the package is intended for source-repository installation until a registry distribution is published.

```sh
uv sync --frozen
make check
```
