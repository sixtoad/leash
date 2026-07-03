package runner

// DOWNSTREAM ONLY — do not send upstream.
//
// This file makes leash default to the container-free *native* backend when the
// user passes neither --runtime nor LEASH_RUNTIME. Upstream stays docker-default;
// native-as-default is a fork product decision ("leash on my real machine"). The
// opt-in native support itself (nativeLauncher, leashd --host, the native
// preflight) lives on feat/runtime-native-poc and is upstream-eligible — only
// this default selection is private.
//
// The default is native on EVERY OS, not just Linux: the intent is "the
// platform's native enforcement, detected by OS". Today only the Linux native
// backend is wired as a runner runtime; on macOS the native path is --darwin
// (ES/NE) and on Windows it is not yet built. On those, defaulting to "native"
// makes the native preflight surface how to get native for that OS (or how to
// opt into --runtime docker) rather than silently containerizing — matching the
// "never a silent docker fallback" rule. Actually dispatching macOS `leash run`
// to --darwin by default is a main.go/darwind concern (issue sixtoad/leash#2),
// tracked separately; until then macOS/Windows default runs stop with guidance.

// defaultRuntimeName is the runtime chosen when neither --runtime nor
// LEASH_RUNTIME is set. It is always native (the low-level newRuntime("")
// default stays docker for direct-construction callers/tests).
func defaultRuntimeName() string { return nativeRuntimeName }
