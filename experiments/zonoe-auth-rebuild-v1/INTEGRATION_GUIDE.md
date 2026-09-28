# Zonoe Server-Driven Auth — Integration Guide

> Current integration guide for branch `test/zonoe-server-driven-auth-flow-v1`.
>
> Baseline: current run31 behavior verified in device testing as broadly working.
>
> Minimum iOS: **iOS 13.0**
>
> Architecture principle: **if the server can return a business value, the client must not hard-code it.** The client owns protocol, state machine, security, formatting, and UI rendering only.

---

## 1. What this module currently does

Current user flow:

```text
First use
  -> enter UDID
  -> enter card/code
  -> GET /appstore?udid=...&code=...
  -> compare server authorization state before/after activation
  -> GET /index/index/apiface?udid=...
  -> Runtime Config
  -> Verify Protocol v2
  -> activation success dialog
       current access level
       expiration time
  -> notice dialog from server JSON
  -> app_update dialog from server JSON when applicable
  -> authorization center

Returning user
  -> saved UDID + card exist
  -> /apiface + Verify
  -> valid: open authorization center directly
  -> expired/revoked/not found: clear saved card only, keep UDID, return to card input
```

Activation errors such as “card already used”, “card not found”, etc. remain in the **same card-entry dialog**. They do not open a separate success/status dialog.

---

## 2. Server-driven rule

Do not hard-code business content that the server already returns.

Server-controlled examples:

```text
message
notice
notice.title
notice.message/content/text
notice.buttons
notice button title/action/url
app_update
app_update title/message/url/force/available/latest_version/latest_build
access_level
permissions
expire / expiration
card/license type
scope
action
code
```

Client-controlled responsibilities:

```text
HTTP request construction
Protocol v2 canonical string
nonce / timestamp
HMAC
state machine
secure local persistence
field formatting
native alert/window rendering
opening server-provided URLs
```

Do not infer authorization capability from card name. Use `access_level` and `permissions` returned by Verify.

---

## 3. Current source layout

```text
experiments/zonoe-auth-rebuild-v1/
├── ZONEntry.m
├── ZONAPIEndpoints.h
├── ZONAPIEndpoints.m
├── ZONNetwork.h
├── ZONNetwork.m
├── ZONActivation.h
├── ZONActivation.m
├── ZONLicenseStatus.h
├── ZONLicenseStatus.m
├── ZONVerify.h
├── ZONVerify.m
├── ZONDylibConfig.h
├── ZONDylibConfig.m
├── ZONDylibVerify.h
├── ZONDylibVerify.m
├── ZONStorage.h
├── ZONStorage.m
├── ZONResponseFormatter.h
├── ZONResponseFormatter.m
├── ZONUI.h
├── ZONUI.m
├── ZONUIV2_Core.inc
├── ZONUIV2_Window.inc
├── ZONUIV2_Prompts.inc
├── ZONUIV2_Display.inc
├── ZONAuthorization.h
├── ZONAuthorization.m
├── ZONAPISmokeCenter.h
├── ZONAPISmokeCenter.m
├── README.md
├── README_V2.md
└── INTEGRATION_GUIDE.md
```

### Main runtime modules

- `ZONEntry.m` — main state machine / orchestration.
- `ZONAPIEndpoints.*` — API endpoint construction.
- `ZONNetwork.*` — GET/POST transport and JSON decoding.
- `ZONActivation.*` — `/appstore` activation request.
- `ZONLicenseStatus.*` — `/index/index/apiface` license state.
- `ZONVerify.*` — high-level Verify adapter.
- `ZONDylibVerify.*` — Protocol v2 request/signature/runtime-config implementation.
- `ZONDylibConfig.*` — Verify configuration and public placeholder secret.
- `ZONStorage.*` — UDID/card/last state persistence.
- `ZONResponseFormatter.*` — diagnostic/authorization-center formatting.
- `ZONUI.*` + `ZONUIV2_*.inc` — floating button, dialogs, notice buttons, authorization center.

### Legacy / diagnostic modules

- `ZONAuthorization.*` — old `/authorization` compatibility path. It is not the current primary user authorization path.
- `ZONAPISmokeCenter.*` — previous full API smoke/diagnostic center. Not required for the normal user flow.

Note: the current CI still compiles `ZONAuthorization.m` for compatibility, but the primary flow in `ZONEntry.m` does not rely on it.

---

## 4. Required build settings

Current CI build command is equivalent to:

```bash
clang -fobjc-arc -dynamiclib \
  -arch arm64 \
  -miphoneos-version-min=13.0 \
  ZONUI.m \
  ZONNetwork.m \
  ZONAPIEndpoints.m \
  ZONAuthorization.m \
  ZONActivation.m \
  ZONLicenseStatus.m \
  ZONVerify.m \
  ZONStorage.m \
  ZONResponseFormatter.m \
  ZONEntry.m \
  ZONDylibConfig.m \
  ZONDylibVerify.m \
  -framework UIKit \
  -framework Foundation \
  -framework Security \
  -framework QuartzCore \
  -framework CoreGraphics \
  -o YourAuthModule.dylib
```

Required frameworks:

```text
UIKit
Foundation
Security
QuartzCore
CoreGraphics
```

Current architecture:

```text
arm64
iOS >= 13.0
ARC enabled
```

---

## 5. API roles

### 5.1 Activation

```text
GET /appstore?udid=<UDID>&code=<CARD>
```

Purpose: submit card/code activation/binding.

Important: the legacy `/appstore` protocol can return the same numeric `code` value for both success and failure in some old server implementations. Therefore the client must **not** treat `/appstore` `code` alone as authoritative activation success.

Current client behavior:

```text
fetch authorization snapshot before activation
-> call /appstore
-> fetch authorization snapshot after activation
-> compare state
-> only continue as success if server authorization state actually changes into a valid state
```

This prevents an already-authorized UDID from making an invalid new card appear successful.

### 5.2 Daily/current authorization state

```text
GET /index/index/apiface?udid=<UDID>
```

Purpose: retrieve current authorization/license status and expiration-related data.

The client consumes the returned JSON as server state. Do not invent a separate local HMAC verification scheme for `/apiface` unless the API contract explicitly defines one.

### 5.3 Runtime Config

```text
GET /index/dylib_verify/config?dylib_key=zonoe.main
```

Purpose: obtain runtime Verify configuration before Protocol v2 verification.

### 5.4 Verify Protocol v2

```text
POST /index/dylib_verify/verify
```

Purpose:

```text
security verification
access_level
permissions
notice
app_update
app_identity
offline_grace_seconds
server_time
token
code / action / message
```

Program logic must use structured fields such as:

```text
ok
code
action
```

Do not parse `message` text to decide business logic.

---

## 6. First activation state machine

Recommended current sequence:

```text
1. Ask for UDID.
2. Save UDID locally.
3. Show card-entry dialog.
4. Read pre-activation /apiface state.
5. Submit /appstore activation.
6. Read post-activation /apiface state.
7. Confirm authorization state changed and is valid.
8. Run Verify v2.
9. Only after Verify succeeds:
   - persist card
   - persist latest Verify state
   - show activation success dialog
10. On user confirmation:
   - show notice
   - show app_update if server says it should be shown
   - open authorization center
```

### Activation failure UI

Failure remains inside the existing card-entry dialog:

```text
Title: 卡密激活
Message: <server returned error message>
Text field: card input
Buttons: 取消 / 激活
```

Do not open a separate failure result dialog for normal card errors.

---

## 7. Activation success UI

Current intended UI is deliberately minimal:

```text
Title: 激活成功

当前等级：<server access_level>
到期时间：<formatted server expiration>

[确定]
```

Do not dump these into the success dialog:

```text
permissions
remaining_seconds
raw message
nonce
sign
ts
token
full JSON
```

Those belong in internal state, diagnostics, or the authorization center as appropriate.

---

## 8. Returning-user flow

When both locally saved UDID and card exist:

```text
floating button tap
-> /apiface
-> Verify v2
```

If authorization is valid:

```text
open authorization center directly
```

Do **not** ask for UDID/card again.

If authorization is expired, revoked, missing, or Verify says authorization is invalid:

```text
clear local card state
keep UDID
show card-entry dialog again
```

Network errors must not automatically erase the saved card.

---

## 9. Notice rendering

`notice` is structured JSON and must be rendered semantically, not dumped as text.

Example server object:

```json
{
  "title": "公告",
  "message": "感谢下载",
  "notice_key": "...",
  "revision": 1,
  "buttons": [
    {
      "title": "知道了",
      "action": "open_url",
      "url": "https://example.com/a"
    },
    {
      "title": "确定",
      "action": "open_url",
      "url": "https://example.com/b"
    }
  ]
}
```

Client UI:

```text
公告

感谢下载

[知道了] [确定]
```

Internal/control fields such as these are not displayed as body text:

```text
notice_key
revision
action
url
buttons raw JSON
```

Each button uses the server-provided `title`, `action`, and `url`.

For `action = open_url`, open the server-provided URL.

Do not hard-code notice button titles or URLs when the server supplies them.

---

## 10. app_update rendering

`app_update` is server-provided update data. The client decides whether to present it, but must not invent update business content when the server provides it.

Supported template variables in the current client:

```text
{app_name}
{current_version}
{current_build}
{latest_version}
{latest_build}
```

Local values:

```text
app_name        -> CFBundleDisplayName, fallback CFBundleName, fallback CFBundleExecutable
current_version -> CFBundleShortVersionString
current_build   -> CFBundleVersion
```

Server values:

```text
latest_version
latest_build
```

Typical flow:

```text
Verify succeeds
-> read app_update
-> evaluate available/show/enabled according to returned object
-> render server title/message
-> substitute template variables
-> execute server-provided URL/action when supported
```

No update object / server says not available -> no update dialog.

---

## 11. Authorization capabilities

Never derive capabilities from the visible card name.

Use:

```text
access_level
permissions
```

Example:

```json
{
  "access_level": "global_plus",
  "permissions": {
    "normal_menu": true,
    "extra_menu": true,
    "extra_features": true
  }
}
```

Protected features should consume the returned permission values directly.

If the server changes permission mapping later, the dylib should not need recompilation just to update the mapping.

---

## 12. Local storage

`ZONStorage` currently persists:

```text
UDID
card
last Verify result
last activation object
```

User-facing authorization center exposes:

```text
清除卡密
清除 UDID
确定
```

Semantics:

```text
清除卡密 -> remove card/authorization cache, keep UDID
清除 UDID -> remove card state and UDID
```

Expired/revoked authorization automatically clears the card state but keeps UDID so the user can enter a new card immediately.

---

## 13. Verify Secret handling

The public GitHub source must **not** contain the real Verify Secret.

Current public source intentionally uses a fixed-length placeholder in `ZONDylibConfig.m`.

Correct release/test workflow:

```text
public source with placeholder
-> CI build
-> download dylib artifact
-> inject real Verify configuration/secret in a controlled environment
-> re-sign dylib
-> package into IPA/tweak
-> re-sign final IPA as required
```

Do not commit the real secret to a public repository.

Do not print the real secret in logs, documentation, screenshots, or chat output.

A dylib built directly from public CI with the placeholder will fail Verify signature validation and can produce errors such as request-signature mismatch.

---

## 14. UI integration

Current module installs its floating button from the dylib constructor in `ZONEntry.m`:

```objc
__attribute__((constructor))
```

After a short delay it:

```text
creates/installs floating UI
assigns tapHandler
routes tap into the current auth state machine
```

If integrating into an existing menu system, you can keep the service/state modules and replace the floating-button bootstrap with your own menu/button callback.

In that case, route your existing button into the equivalent of the current `ZONRoute()` logic.

---

## 15. Files to copy into another dylib project

### Required for the current flow

```text
ZONEntry.m
ZONAPIEndpoints.h
ZONAPIEndpoints.m
ZONNetwork.h
ZONNetwork.m
ZONActivation.h
ZONActivation.m
ZONLicenseStatus.h
ZONLicenseStatus.m
ZONVerify.h
ZONVerify.m
ZONDylibConfig.h
ZONDylibConfig.m
ZONDylibVerify.h
ZONDylibVerify.m
ZONStorage.h
ZONStorage.m
ZONResponseFormatter.h
ZONResponseFormatter.m
ZONUI.h
ZONUI.m
ZONUIV2_Core.inc
ZONUIV2_Window.inc
ZONUIV2_Prompts.inc
ZONUIV2_Display.inc
```

### Compatibility-only / optional

```text
ZONAuthorization.h
ZONAuthorization.m
```

### Diagnostic-only / optional

```text
ZONAPISmokeCenter.h
ZONAPISmokeCenter.m
```

If you remove optional modules, also remove them from your build command/project target.

---

## 16. Device validation checklist

Before calling an integration complete, verify all of these on device:

```text
[ ] Invalid/non-existent card stays in card-entry dialog
[ ] Already-used card stays in card-entry dialog
[ ] Valid card activates successfully
[ ] Success dialog shows only access level + expiration time
[ ] Pressing OK continues to notice
[ ] Notice title/body are server-driven
[ ] Notice buttons are generated from server JSON
[ ] Each notice button executes its own server-provided URL/action
[ ] app_update appears only when the returned object says it should
[ ] app_update text is server-driven
[ ] Template variables render correctly
[ ] Returning user does not see UDID/card activation again
[ ] Authorization center opens directly for valid authorization
[ ] Expired authorization clears card only and prompts for a new card
[ ] Network failure does not erase a valid saved card
[ ] Different card classes produce different server access_level/permissions as configured
[ ] Real Verify configuration passes Protocol v2 signature validation
[ ] Public-source placeholder build is never mistaken for a final configured build
```

---

## 17. Current integration boundary

The current module is intentionally server-driven.

The correct long-term rule is:

```text
Server decides business data and policy values.
Client executes the protocol and renders those values.
```

Do not add local copies of server business configuration unless there is a documented offline/fallback requirement.

When the server adds a new field:

```text
1. Preserve the field.
2. Decide whether it is control data, display data, or security data.
3. Render it semantically if user-facing.
4. Do not dump raw JSON into normal user dialogs.
5. Do not silently invent a value when the field is absent.
```

---

## 18. Current CI reference

Workflow:

```text
.github/workflows/zonoe-auth-rebuild-v1.yml
```

Current artifact name:

```text
ZonoeServerDrivenAuthFlowV1-arm64-ios13
```

The CI artifact is a public-source build and therefore uses the placeholder Verify Secret. A configured test/release dylib must be produced separately without committing the real secret.
