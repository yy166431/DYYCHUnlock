# DYYCHUnlock Privacy Fix

This fixed hook targets the supplied ARM64 dylib with SHA-256
`447792aacd73cec65cb850da86e39f8915cdd6526424874016e2ed0c44c9bc69`
and Mach-O UUID `79AE6B44-7FE2-3C31-9765-09ED0C83C298`.
It retains v8's activation timing and flags with an additional image UUID check.
The old SDK configuration poisoning and generic alert suppression are removed.

## Confirmed Outbound Routes

| Route | Binary evidence | Interception |
| --- | --- | --- |
| Concert order reporting | `0xc3932c`, `0xc393c8`, `0xc39408` send the same order through three paths; event/table `dy_order_create_maybe_suc` | All three business entry points |
| LeanCloud | Three `WPLeanCloudHandler` save methods; SDK `LCPaasClient` final sender at `0x1201840` | Save methods, final request method, archived-request replay, SDK sessions |
| Custom HTTP | `potpiutoideidcs plxmnqazxcvbnm:data:callback:` at `0xef4c2c`; POST `http://<configured-host>/operate` | Source method, configured `logUrl` host and author-created session tagging |
| Supabase | `mnxbvczqwpalsdf:data:withFilters:completion:` at `0xf2b420`; `upsertRecordInTable` at `0xf2db6c` | Source method, shared client request method, auth requests, configured host/session |
| Message reporting | `pytpiutoideidcs pp60f925ab47ed:`; `/wx/ws/receive_msg`, sender `0x929f40` | Source method plus transport |
| Account/device reporting | `plxqzmnwfdsajkl:`; `/wx/receive_data_dy` | Source method plus transport |
| Bark notifications | Several `potpiutoideidcs` push wrappers; `api.day.app`, sender `0xf231c4` | Push methods and endpoint |
| Heartbeat and remote commands | `SRWebSocketHelper`, `ws://<configured-host>/wx/terminator`; headers include device/account identifiers | Timer, connect, reconnect and send methods; SocketRocket open/write |
| Remote configuration | `potpiutoideidcs +load` callback fetches Apifox configuration at `0xeb3d5c`; Supabase endpoint is configurable | Configuration endpoint and author session origin |
| Update check | `WPCheckVersionTool checkVersionFromFir`, sender `0xc856a4` | Plugin update methods and endpoint |
| Legacy HTTP | `ZXHttpRequest baseUrl:postData:callBack:` calls `NSURLConnection` at `0x100a688` | Legacy synchronous/asynchronous APIs and author call provenance |

The v8 selector `requestWithMethod:url:params:progress:success:failure:` is absent
from this binary. Its LeanCloud interception does not cover the independent
custom HTTP, Supabase and push routes. Several author sessions explicitly clear
proxy configuration, so absence from an ordinary proxy capture is insufficient.

Order and device payloads include fields such as `userID`, `phone`, `account`,
`awxID`, `awxNickName`, `goodsName`, `buyCount`, `did`, `p_phone`, `d_info`, and
`last_open`. Credentials, recipient keys and raw account values are not logged by
the companion or included here.

## Build And Install

GitHub Actions `build-dyychu` produces one artifact, `DYYCHUnlock-fixed-arm64`,
containing `libDYYCHUnlock.dylib`, instructions and the dependency preparation tool.
Replace the old v8/v9 hook with this library. The fixed hook must load before the plugin's
startup requests. Injection order alone is not a verified dependency guarantee.
The included script creates a separate copy with a required companion dependency:

```powershell
python prepare_private_copy.py "C:\path\libswiftMetal_patched.dylib" --check
python prepare_private_copy.py "C:\path\libswiftMetal_patched.dylib" --output "C:\bundle\libswiftMetal_private.dylib"
```

Place the compiled `libDYYCHUnlock.dylib` in `C:\bundle` first. The script preserves all code,
data sections and existing library ordinals, verifies the input hash, and refuses
to overwrite the original. The new copy and fixed hook must remain in the same
directory inside the injected app because the dependency uses `@loader_path`.
Re-sign the modified copy using the injection tool. Do not load the original and
the private copy together. Use only the new fixed hook alongside the private copy.

An incorrect install directory or missing companion causes a loader error before
the plugin starts. Revert to the original two-library setup to undo this change.

## Validation And Limits

The workflow tests domain boundaries, callback behavior, idempotent installation,
normal request pass-through, cancelled telemetry tasks and header-only dependency
changes. The Objective-C tests use mocks and Foundation; they do not execute the
target plugin. Compilation and these tests cannot certify iOS behavior.

Before treating a device as isolated, validate cold launch, sign-in, opening the
concert view, ordinary feature operation, a test order event, background/resume,
and Wi-Fi/mobile-data changes. Confirm both source hooks and network denials, and
check traffic with an independent device/gateway capture that is not bypassed by
the plugin's proxy settings. Review any `ABI mismatch` log as a failed hook.

These are the identified routes in this exact sample, not a proof that an unknown
future build or dynamically generated endpoint cannot leak. Remote-only features
can fail while isolated; cached configuration and the actual device must be
checked. Prior server records remain outside the scope of local blocking.
Previously queued background tasks and old local telemetry archives require
device-side inspection. The companion suppresses known archive replay but does
not delete the user's files. Removing it can re-enable reporting.
