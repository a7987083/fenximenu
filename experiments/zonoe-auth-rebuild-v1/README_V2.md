# ZonoeAuthRebuild V2

Server-driven Objective-C client flow for `zonoe.main`.

- Protocol v2 Verify from generator 2.2.0.
- No `Index::dylib()` or `Index::apiface()` dependency.
- Manual UDID -> card activation -> server response display -> notice -> authorization center.
- Known response keys are rendered with Chinese labels; unknown keys remain visible.
- Card/UDID can be cleared from the authorization center.
- Public source contains a fixed-length Verify Secret placeholder only; the real secret is injected only into the final test artifact.
