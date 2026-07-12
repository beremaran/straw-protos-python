# Straw Python protocol bindings

The private `straw-protos` distribution provides generated bindings under `straw_protos` plus equivalent
registration-signing helpers.

```python
from straw_protos.straw.v1 import straw_pb2
```

Every release matches the same immutable `straw-protos` tag and records exact provenance. During stealth, install
only from an exact private Git tag; nothing is published to PyPI.

```sh
uv sync --frozen
make check
```
