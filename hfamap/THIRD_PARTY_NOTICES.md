# Third-party notices

HFAMap v2.3.9 links Dobby as a static library during CI.

- Project: `jmpews/Dobby`
- Pinned commit: `5dfc8546954ce3b3198132ab13fddb89ee92cdd7`
- License: Apache License 2.0
- Upstream: <https://github.com/jmpews/Dobby>

The local compatibility header contains the arm64 register context and public
instrumentation declarations required by HFAMap. The implementation is built
from the pinned upstream source; no prebuilt opaque binary is committed.
