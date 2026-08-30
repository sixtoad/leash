- source_spec: `docs/implementation-artifacts/spec-leash-74-ipv4-byte-order.md`
  summary: Replace or correct the manual Go/C connect-event and connect-policy ABI mirrors so field offsets and ring-buffer decoding are verified, not only total sizes.
  evidence: Clang reports `connect_policy_rule.hostname` at byte 14 while `ConnectPolicyRuleBPF.Hostname` is at byte 16 because of `_pad0`; separately, `binary.Read` does not consume the C event padding between `dest_port` and `result`, so hostname/result decoding is shifted even though both structs have size 192.
- source_spec: `docs/implementation-artifacts/spec-leash-88-release-recovery.md`
  summary: Add an atomic cross-process lock or registry-side conditional publication for native release names.
  evidence: #88 repeats Git tag, GitHub release, and manager-tag checks immediately before mutation, but GHCR push exposes no conditional create-only operation, so two independently authorized publishers can still race in the final check-to-push interval; this predates the recovery path and needs a dedicated coordination design.
