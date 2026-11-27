"""Late-bound access to ``app.main`` for code that is being moved out of it.

Moved flows still depend on state and helpers that live in ``app.main``
(container, MP VM session, remaining orchestration). Resolving them at call
time avoids an import cycle and keeps the existing patch points on
``app.main`` working. Uses of ``host`` disappear as those pieces move out.
"""

from __future__ import annotations

from typing import Any


class _MainHost:
    def __getattr__(self, name: str) -> Any:
        from .. import main

        return getattr(main, name)

    def __setattr__(self, name: str, value: Any) -> None:
        # Moved code that used to rebind an app.main global keeps rebinding it there.
        from .. import main

        setattr(main, name, value)


host = _MainHost()
