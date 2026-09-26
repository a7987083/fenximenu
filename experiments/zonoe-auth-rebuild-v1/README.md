# Zonoe Auth Rebuild V1

Clean rebuild after removing prior H5GG auth experiments.

Core split:
- `ZONUI.m`: floating button + independent UDID/card dialogs + info display
- `ZONNetwork.m`: HTTP transport only
- `ZONActivation.m`: current software-source card activation + legacy status
- `ZONVerify.m`: generated Protocol v2 verifier adapter
- `ZONEntry.m`: thin orchestration

Notification Key: `20260926`
