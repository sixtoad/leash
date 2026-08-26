- source_spec: `docs/implementation-artifacts/spec-leash-74-ipv4-byte-order.md`
  summary: Replace or correct the manual Go/C connect-event and connect-policy ABI mirrors so field offsets and ring-buffer decoding are verified, not only total sizes.
  evidence: Clang reports `connect_policy_rule.hostname` at byte 14 while `ConnectPolicyRuleBPF.Hostname` is at byte 16 because of `_pad0`; separately, `binary.Read` does not consume the C event padding between `dest_port` and `result`, so hostname/result decoding is shifted even though both structs have size 192.
