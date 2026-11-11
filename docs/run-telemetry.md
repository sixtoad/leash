# Run telemetry

Walk/Warren can set `LEASH_TELEMETRY_RUN_ID` in Leash's **host launcher
environment** to opt into run observability, including interactive runs. Walk creates a
private named FIFO and passes its absolute path in `LEASH_TELEMETRY_PIPE` on the
host launcher. Leash sends optional records only through that channel; workload
stdout, stderr and exit status are preserved. No network listener, connection,
mount or sandbox permission is added. The FIFO lives outside workspace and
trace artifact trees, carries redacted bytes without raw disk staging, and works
through native sudo without changing sudo policy. Standalone Leash callers must
supply the same private FIFO with a reader; standalone Walk configures it
automatically when telemetry is enabled. The opt-in
does not set `--machine-output` or disable TTY interaction. Initialization consumes
the host-only secret list and FIFO setting before mount setup or any launcher
children and runs once. Those settings are also removed from explicit workload
environment options. A missing or unsafe FIFO disables optional telemetry; there
is no fallback to shared stderr.

Every record is NDJSON with `schema="warren.run-telemetry/v1"`, `source="leash"`,
`run`, `type`, UTC millisecond `timestamp`, and `agent=null`, `dispatch_id=null`.
This is the common BME/Walk/Warren envelope. Existing human diagnostics and
the enforcement-ready text line retain their existing destinations; consumers must
use the separate optional channel and select JSON records by schema and source.

| Type | Additional fields |
| --- | --- |
| `phase` | `name`, `start`, `end`, `duration_ms`, `status=ok/error` |
| `leash_audit` | `source_offset_bytes`, either redacted `message` or structured `payload` |
| `truncation` | `file`, `bytes_dropped`, `location`, `status=truncated` |
| `error` | `file=leash-audit.ndjson`, `reason`, `status=unavailable` |
| `leash_export` | terminal `status=complete/incomplete`, `source_bytes_dropped`, `event_bytes_dropped` |

The startup spans wrap the existing launcher calls, in order: `image_prepare`
(ensure images and validate the manager), `provision` (start the target and
prepare its cgroup), `enforcement` (start the enforcer), and `attach` (wait for
the existing enforcement-ready gate). `cleanup` measures backend removal.
Native uses the same names; image preparation is its measured no-op.
Durations use Go's monotonic clock; start/end use wall time. These spans do not
claim to cover unrelated launcher setup or the agent lifetime: Walk measures
the enclosing run. Failures report status without recording raw error text.

The audit reader opens with no-follow/nonblocking flags and checks the opened
inode against its regular-file snapshot, rejecting hardlinks and nonregular files.
After the audit producer stops, export reads the existing `events.log` before
temporary directories are removed. It does not redirect `LEASH_LOG_DIR`, copy
raw logs into another file, or change required audit initialization failures.
With kept containers or failed producer teardown, export captures the source
size at export time; later events are outside that snapshot. A missing,
unreadable, replaced or symlink source produces an optional error record.

The output FIFO must have private permissions beneath a private directory. Leash
opens it without following symlinks or blocking for a reader, validates FIFO type,
single link and snapshot inode, rejects stdio aliases, and uses close-on-exec.
The optional worker owns its descriptor; governed children never inherit it.

## Privacy and bounds

Redaction occurs before bytes reach the telemetry pipe. Credential-named host
environment values (at least eight characters, matching BME #415), known
provider token patterns, credential fields regardless of value length,
Authorization/Cookie headers, URL passwords, private keys and opaque grant
fields are scrubbed. Multiline keys and incomplete trailing records are never
exported as partial secrets. JSON audit payloads are scrubbed recursively.

The host may provide `LEASH_TELEMETRY_SECRET_VALUES` as a JSON array of exact
known secrets or grant contents, including arbitrary fake test tokens. It is
limited to 64 KiB and 256 entries, consumed/unset before launching children,
and removed from explicit workload environment options. Never include it in
workload arguments. Literal and JSON-escaped forms and multiline components
are scrubbed. This does not discover arbitrary secrets unknown to the host
that do not match a credential pattern or field.

`LEASH_TELEMETRY_PRESERVE_HOST_PATHS=false` (or `0`) replaces known HOME,
working-directory and temporary-directory prefixes with `${HOST_PATH}`;
preservation defaults to true for single-owner hosts.

`LEASH_TELEMETRY_MAX_FILE_BYTES` defaults to 268435456 (256 MiB), with a minimum
of 4096. It caps the combined emitted Leash NDJSON bytes, reserving 2048 bytes
for a final loss record. Audit scanning is bounded by the same source-byte
budget (plus at most one 64 KiB read fragment); records larger than 4 MiB are
withheld in full. `bytes_dropped` counts original audit-source bytes, including
newlines, for withheld records and unread tail (`file=leash-audit.ndjson`,
`location=audit_export`). Omitted phase/error records count their serialized
bytes separately (`file=leash-events.ndjson`, `location=record_limit`). Oversized lines conservatively
suppress possible following private-key material until an end marker. There
is no intermediate partial-record file.

Optional output uses one worker with a nonblocking 64 MiB serialized-record
queue, including its in-flight records. It batches up to 512 records or 256 KiB
(one larger complete record is allowed), coalescing small batches for 25 ms.
Redaction precedes queue admission; memory also includes the bounded current
audit record and the worker's batch copy. Queue pressure stops further scanning
and accounts for the rejected record and unread snapshot tail. A partial write
counts its entire incomplete record as lost. Audit scanning has a separate
30-second elapsed budget, checked between 64 KiB fragments; exceeding it records
the unread source bytes as loss.

Final optional drain waits at most one second, independently of workload
cancellation. Repeated close calls do not repeat an expired wait. After timeout,
queued records are discarded and accounted for; the one isolated in-flight
writer can finish later and is never replaced with additional workers. Its
delivery remains unconfirmed until the write returns. Required teardown and
workload exit selection do not wait for that writer. Early startup errors also
close the optional worker.

A failed/short write disables further export. Optional telemetry never writes
console warnings: even a small warning can lock shared stderr and block a later
required diagnostic. A received complete `leash_export` marker confirms eventual
delivery of the audited snapshot and events without known loss. The caller may
stop waiting before delivery finishes: a drain timeout alone does not prove
missing evidence, although the worker may conservatively report incomplete.
Walk records missing/incomplete terminal delivery in its independent
telemetry sink and manifest. Loss footers remain best effort when the output
channel itself fails or stays blocked until process exit.

Leash does not prune logs or traces. Warren owns the shared defaults of 2 GiB
per run, 30 days and 50 GiB completed telemetry; standalone collectors own their
retention. Existing operational audit storage retains its existing lifecycle.

Escaped credential assignments embedded in audit prose or nested text are redacted
before export, including four JSON escape layers and quoted/backslash values.
Malformed recognizable credential values withhold the remaining text. Complete
assignments retain surrounding context; processing copies each text slice once.
