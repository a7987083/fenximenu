# Zonoe Auth Rebuild V1

Clean restart of the injected iOS authentication UI.

## Target flow

1. Tap floating button.
2. If no saved UDID: show UDID input dialog and save it.
3. Check current legacy authorization for that UDID.
4. If unauthorized/expired: show card-key input dialog.
5. Submit UDID + card key to the existing activation endpoint and display the server result.
6. After activation, run Dylib Verify v2.
7. On later taps, skip card input while authorization is valid and show authorization information, permissions, notice, app update and server message.

## Source of truth

- Dylib Verify protocol: generated Objective-C package supplied by the project owner.
- Legacy card activation/status API: existing backend implementation in `a7987083/app-`.
- iOS deployment target: 13.0+.

## Rules

- No V1-V6 experimental source is reused as the application entry point.
- Verification secrets must never be committed to this public repository.
- Server error messages are displayed rather than replaced with locally invented result codes.
