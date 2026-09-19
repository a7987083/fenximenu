# Development Changelog

## v0.1.0
- Added bounded app-local image discovery.
- Added structural family classifier for Legacy AP and C4M0.
- Added 160-byte descriptor locator using stable selectors rather than randomized class names.
- Added C4M0 `loadConfig:`/`loadPolicies` IMP ownership reporting with `dladdr`.
- Added read-only analysis JSON and diagnostic logs.
- Added CI guard preventing runtime hook/memory-write code from entering v0.1.
