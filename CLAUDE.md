# Notes for Claude

- CI and release builds are deliberate, never routine: Actions minutes are
  scarce (private repos' Actions do not run; chatir's ci.yml is off by hand).
  Verify locally (`cargo fmt`, `clippy -D warnings`, tests). Never dispatch a
  workflow or push a tag to see whether something builds. A release is built
  once, when everything it ships is verified, merged and built as it should
  ship; not a version that is replaced hours later.
- The lab's repos (pushir, chatir, pasa, siroh, tydig, irp, irnet, pairir)
  release together at one version: v0.1.20, then v0.2.0 when public.
- Sync stays compatible with peers from v0.4.11 on (ALPN `pasa/6`): change
  the transport only when nothing else works, and then so that old and new
  still talk (the old form beside the new). That is the ALPN, `swap`'s
  frames, pairing payloads and QR text, lanes and wakes (pushir), relay TLS
  and `psk` (irnet), short codes (pairir). Hardening never costs a sync:
  what cannot be had is said, and sync goes on; a change that could delay
  or drop one comes with a test that it still gets through.
