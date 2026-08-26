---
title: 'Leash #74: canonical IPv4 and port byte order'
type: 'bugfix'
created: '2026-08-26'
status: 'done'
review_loop_iteration: 0
baseline_commit: 'fd8e0c1deb978d1871e080cd09a7f9e9c394c406'
context:
  - '{project-root}/docs/design/ARCHITECTURE.md'
---

<frozen-after-approval reason="human-owned intent — do not modify unless human renegotiates">

## Intent

**Problem:** On little-endian Linux, the LSM reads IPv4 addresses and ports from `sockaddr_in` as native integers but compares and reports them as though those integers were already canonical. An asymmetric address such as `192.168.1.1` consequently becomes `1.1.168.192`, and literal IP/port policy values cannot reliably match kernel connect/sendmsg inputs.

**Approach:** Define one semantic representation across the boundary: IPv4 `a.b.c.d` is the numeric value `a<<24 | b<<16 | c<<8 | d`, while ports are ordinary host numeric values. Convert both fields from network byte order at the two BPF `sockaddr_in` ingestion points; preserve those canonical values unchanged in policy maps, DNS-cache keys, events, and Go structs; format events directly from the canonical values.

## Boundaries & Constraints

**Always:** Reproduce with asymmetric octets; cover TCP `socket_connect` and UDP/DNS `socket_sendmsg`; keep BPF and Go struct layouts identical; test literal policy value retention and TCP/UDP event formatting; compile regenerated eBPF artifacts; preserve current hostname, wildcard, default-policy, protocol, and DNS-cache behavior.

**Ask First:** Any ABI layout change, IPv6 support, policy syntax change, or broader network-enforcement redesign.

**Never:** Add reversed-address compatibility entries, accept both byte orders, special-case particular resolvers, weaken enforcement, or patch unrelated review findings.

## I/O & Edge-Case Matrix

| Scenario | Input / State | Expected Output / Behavior | Error Handling |
|----------|---------------|----------------------------|----------------|
| Literal TCP policy | Policy `allow net.send 192.168.1.1:443`; `socket_connect` receives network-order sockaddr bytes | BPF compares canonical IP `0xC0A80101` and port `443`; event displays `192.168.1.1:443` | Nonmatching address or port follows existing rule/default decision |
| UDP DNS send | Policy permits `192.168.1.1:53`; `socket_sendmsg` receives an explicit IPv4 destination | BPF uses the same canonical values and event displays UDP `192.168.1.1:53` | Null/non-IPv4 destination keeps existing behavior |
| DNS cache lookup | Canonical IP key maps to a hostname | Policy expansion, BPF cache lookup, event cache update, and userspace cache use the same key | Existing unresolved-host behavior is unchanged |

</frozen-after-approval>

## Code Map

- `internal/lsm/bpf/lsm_connect.bpf.c` -- reads TCP and UDP destination sockaddr fields, matches policy/DNS maps, and emits connect events.
- `internal/lsm/common.go` -- parses literal policy IPs and defines common connect policy values.
- `internal/lsm/net_connect.go` -- defines map/event ABI mirrors, expands hostname policies, manages DNS keys, and formats emitted events.
- `internal/lsm/net_connect_test.go` -- regression coverage for canonical literals, policy map values, DNS keys, and TCP/UDP formatting.

## Tasks & Acceptance

**Execution:**
- [x] `internal/lsm/bpf/lsm_connect.bpf.c` -- convert IPv4 and port fields with BPF endian helpers immediately after both sockaddr reads, and document the canonical representation.
- [x] `internal/lsm/common.go` and `internal/lsm/net_connect.go` -- centralize/document canonical IPv4 conversion and remove the event port double-swap while leaving ABI layouts intact.
- [x] `internal/lsm/net_connect_test.go` -- reproduce the old reversal and verify literal policy/map values, DNS-cache keys, and formatted asymmetric TCP and UDP events.

**Acceptance Criteria:**
- Given `192.168.1.1:443`, when the literal rule and TCP event traverse their respective Go/BPF representations, then both use IP `0xC0A80101`, port `443`, and display `192.168.1.1:443`.
- Given UDP DNS traffic to `192.168.1.1:53`, when `socket_sendmsg` processes it, then the same canonical representation is used for policy matching, DNS lookup, and event output.
- Given existing hostname and wildcard rules, when policies are loaded, then their expansion/default semantics remain unchanged.
- Given a little-endian build host, when the eBPF source is regenerated, then clang/bpf2go compilation succeeds without struct-layout changes.

## Spec Change Log

## Design Notes

`sockaddr_in` stores IP and port bytes in network order. On little-endian Linux, directly assigning these fields to integers yields byte-reversed numeric values. BPF must use `bpf_ntohl`/`bpf_ntohs` at ingress. Thereafter all map keys, rule values, event fields, and Go values carry canonical semantic numbers; serialization remains the platform-native behavior of the BPF/Go ABI.

## Verification

**Commands:**
- `go test ./internal/lsm ./internal/transpiler` -- focused policy and event regressions pass.
- `make lsm-generate` -- both LSM hooks compile with the endian conversions.
- `go test ./...` -- the full Go unit suite passes with generated LSM bindings.
- `go vet ./...` -- static checks pass.
- `make build` -- release-style command binaries build successfully.

## Suggested Review Order

**Kernel boundary**

- Convert TCP sockaddr fields once before policy, cache, and event processing.
  [`lsm_connect.bpf.c:339`](../../internal/lsm/bpf/lsm_connect.bpf.c#L339)

- Apply the identical conversion to UDP and DNS sendmsg destinations.
  [`lsm_connect.bpf.c:387`](../../internal/lsm/bpf/lsm_connect.bpf.c#L387)

**Canonical userspace representation**

- Centralize IPv4 numeric conversion shared by policies, maps, caches, and events.
  [`common.go:575`](../../internal/lsm/common.go#L575)

- Format canonical event addresses and host-order ports without a second swap.
  [`net_connect.go:438`](../../internal/lsm/net_connect.go#L438)

**Boundary regression coverage**

- Compile-time guards freeze only the address and port ABI offsets in scope.
  [`lsm_connect.bpf.c:73`](../../internal/lsm/bpf/lsm_connect.bpf.c#L73)

- Hook-contract tests independently protect TCP and UDP endian conversion calls.
  [`net_connect_test.go:45`](../../internal/lsm/net_connect_test.go#L45)

- Literal policy tests reject reversed compatibility while checking native map values.
  [`net_connect_test.go:77`](../../internal/lsm/net_connect_test.go#L77)

- Event tests cover canonical DNS keys and asymmetric TCP and UDP display.
  [`net_connect_test.go:130`](../../internal/lsm/net_connect_test.go#L130)

**Deferred pre-existing defect**

- Keep the independently confirmed full-ABI padding defect outside issue #74.
  [`deferred-work.md:1`](deferred-work.md#L1)
