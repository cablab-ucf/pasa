# Notes for Claude

- CI and release builds are deliberate, never routine: Actions minutes are
  scarce (private repos' Actions do not run; chatir's ci.yml is off by hand).
  Verify locally (`cargo fmt`, `clippy -D warnings`, tests). Never dispatch a
  workflow or push a tag to see whether something builds. A release is built
  once, when everything it ships is verified, merged and built as it should
  ship; not a version that is replaced hours later.
- The lab's repos (pushir, chatir, pasa, siroh, tydig, irp, irnet, pairir)
  release together at one version: v0.1.20, then v0.2.0 when public.
- pasa's pushes depend on pasa alone, as chatir's on chatir: its process
  outlives its activity (pushir's service lives in it), and it should
  call `Pushir.hold` from its activity in sight and show `Pushir.held()`
  (not yet done).
  Each pushir bump is checked on a phone with pasa swiped away and locked.
