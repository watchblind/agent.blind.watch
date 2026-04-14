# Agent Reconnection & Crash-Safe Buffering — Design

**Status:** Approved (pending user spec review)
**Date:** 2026-04-14
**Scope:** `agent.blind.watch` Go agent — `internal/transport`, `internal/wal`, `internal/scheduler`
**Out of scope:** Settings UX (item 3), uptime graph UI (item 4), backend/server changes (server already accepts the messages we'll send).

---

## 1. Problem

Two related reliability gaps observed in production:

1. **Process-death data loss.** `scheduler.bufferSnapshot()` accumulates collected snapshots in an in-memory slice (`batchBuf`) for up to 10 minutes before encrypting and writing to WAL on the batch boundary. Crash, OOM, kill -9, or power loss anywhere in that window loses up to 10 minutes of metrics. The same pattern (5s window) applies to log batches.
2. **Slow / silent reconnection.** `transport.Connection` reconnects on TCP error, but has no WS ping/pong heartbeat and no read deadline. Half-open connections (NAT timeout, server-side unclean shutdown, network partition) go undetected for many minutes — the agent thinks it's connected but no data flows.

Plus latent issues:

- `wal.Append` calls `f.Sync()` on a read-only `os.Open` handle, so the data fsync is a no-op. A crash between `os.WriteFile` returning and the kernel flushing leaves a missing or partial WAL file.
- `os.WriteFile` is not atomic — a crash mid-write produces a torn file that fails JSON parsing on recovery.
- On disconnect, items already in `Connection.sendCh` are still delivered when the WS reconnects, while the WAL replay also re-sends them → duplicate delivery.

## 2. Goals

- Snapshots are durable on disk within ~5 ms of collection. Worst-case loss = the single in-flight snapshot at moment of power failure.
- Network outages of 2–3 hours (and well beyond) buffer locally and drain on reconnect, in order, without duplicates.
- Half-open connections are detected within ~45 s.
- 10-minute batching semantics preserved end-to-end (server, AE storage, dashboard see the same shape of `batch` messages they do today).
- No new runtime dependencies; static binary (`CGO_ENABLED=0`) preserved.

## 3. Non-goals

- Persisting `live` / `live_log` messages — they are display-only by design.
- Server-side changes — server already handles `wal_sync` idempotently.
- Replacing the WAL with an embedded DB (sqlite, bbolt) — would require CGO or pull in a runtime dep; rejected.
- Settings UX, uptime graph UI — separate specs.

## 4. Design

### 4.1 On-disk format

Each in-progress batch is one **NDJSON file** in the WAL directory:

```
<batch_id>.open       # in-progress, append-only
<batch_id>.wal        # finalized, awaiting ack
```

File layout (one JSON object per line):

```
{"meta":{"batch_id":"b_1711900800_ag_abc","agent_id":"ag_abc","epoch":3,"started_at":1711900800}}
{"epoch":3,"timestamp":1711900810,"enc_payload":"<base64>","crc":1234567890}
{"epoch":3,"timestamp":1711900820,"enc_payload":"<base64>","crc":2345678901}
...
```

- Line 0 is always the meta record.
- Lines 1..N are encrypted `BatchEntry` records, one per collected snapshot, with a CRC32C of the JSON body (excluding the `crc` field) for torn-write detection.
- File grows during the batch window; never rewritten in place.

### 4.2 Write path (per snapshot)

```
collect()
  -> encrypt(snapshot, current DEK)        # in-memory only
  -> wal.AppendEntry(open_batch_id, entry) # serialize -> O_APPEND write -> fsync(file)
  -> (no in-memory buffer)                 # batchBuf is removed
```

The first append for a new batch window also writes the meta line and `fsync`s the parent directory (so the file's existence is durable).

### 4.3 Batch boundary (every 10 min, wall-clock aligned)

```
1. wal.Finalize(open_batch_id)
     - fsync file
     - rename .open -> .wal (atomic on POSIX; equivalent on Windows via MoveFileEx replace)
     - fsync parent directory
2. read all entries from .wal (already encrypted)
3. send batch message with those entries
4. on ack: delete .wal, fsync parent dir
```

### 4.4 Crash recovery on startup (extends `syncWAL`)

```
for each *.open file:
    parse line-by-line, validate CRC, drop torn final line if invalid
    if zero valid entries: delete file, continue
    rename .open -> .wal (preserves batch_id)
    enqueue for wal_sync

for each *.wal file (in start-timestamp order):
    send wal_sync message (1s spacing between sends)
    await ack -> delete
```

Server already accepts `wal_sync`; no protocol change required.

### 4.5 Long-outage capacity

| Limit | Today | New |
|---|---|---|
| Max files | 1,000 | **2,000** |
| Max total size | 500 MB | **1 GB** |
| Max age | (none) | **7 days** |

Eviction order on full: oldest-first by start_timestamp (today's behavior, preserved). Files older than 7 days are dropped during enforcement with a `WARN` log so we notice abnormally-long offline agents.

At 1 batch per 10 min of typical idle metrics (~60 entries × ~1 KB each = ~60 KB per batch), 2,000 files = ~120 MB of WAL — comfortably under the 1 GB cap, and ~14 days of capacity.

### 4.6 Reconnection hardening

In `transport.Connection`:

| Change | Today | New |
|---|---|---|
| WS ping interval | none | **15 s** (gorilla websocket `WriteControl` with `PingMessage`) |
| WS read deadline | none | **45 s**, refreshed on every ping ack and on every received message |
| Treat as connected | on TCP dial success | **on receipt of `connected` message** |
| Failure log frequency | every attempt | **first failure + once per minute thereafter**; reset on success |
| `sendCh` on disconnect | retained, replayed on reconnect | **drained on disconnect** (WAL handles re-delivery, prevents duplicate sends) |
| Backoff | 1 s → 60 s + 0–1 s jitter | unchanged |

`writePump` already drops rate-limited categories; behavior unchanged.

### 4.7 Atomicity & fsync correctness

All WAL writes go through a small helper:

```
func writeAndSync(path string, data []byte) error {
    f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0600)
    ...
    if _, err := f.Write(data); err != nil { ... }
    if err := f.Sync(); err != nil { ... }
    return f.Close()
}
```

Plus a `fsyncDir(dir string)` helper called after `Create`, `Rename`, and `Remove`. The current `os.Open(...).Sync()` no-op is replaced.

For the meta line and finalize-rename, atomic write-temp-then-rename is used. For per-entry appends, append-with-fsync is sufficient — partial line on crash is detected and dropped via CRC during recovery.

### 4.8 Observability

Three counters, exposed via the existing `tview` dashboard and logged on reconnect:

- `wal_pending_files` (int)
- `wal_pending_bytes` (int64)
- `seconds_since_last_ack` (int)

One log line on reconnect after a long outage:

```
[ws] reconnected after 1843s, draining 18 pending WAL batches (1.1 MB)
```

## 5. Component impact

| Module | Change |
|---|---|
| `internal/wal/wal.go` | New API: `OpenBatch(batch_id, meta) -> *OpenBatch`, `(*OpenBatch).Append(entry)`, `(*OpenBatch).Finalize()`. Existing `Append`, `Pending`, `Ack` retained for log batches and back-compat. Add `enforceTTL`, fix fsync, add atomic helpers. |
| `internal/scheduler/scheduler.go` | Replace `batchBuf` with an `*OpenBatch` opened on first collect of a window. `bufferSnapshot` becomes `appendToOpenBatch`. `sendBatch` finalizes then sends. `flush` finalizes then `SendSync`. Recovery extended in `syncWAL`. |
| `internal/transport/ws.go` | Add ping ticker, read deadline, `connected`-message gate, log throttling, `sendCh` drain on disconnect. |
| `internal/logtail/...` | Apply same NDJSON pattern to log batches (5s window) — same shape, smaller scale. |
| `internal/dashboard/...` | Surface the three new counters. |

## 6. Backward compatibility

- Pre-existing `.wal` files (legacy single-`Entry` JSON format) are still recognized in `syncWAL` via the existing fallback path in `deserializeWALEntries`. They drain naturally and are never written again.
- No protocol or server change. `wal_sync` already exists and accepts the same `batch` shape.

## 7. Testing

- **Unit:** WAL append + recovery (torn final line, missing CRC, empty file, meta-only file, missing meta).
- **Unit:** `writeAndSync` and `fsyncDir` happy + error paths.
- **Integration:** scheduler crash mid-window via fault injection (kill goroutine after N appends), restart, assert `wal_sync` includes the surviving entries in correct order, no duplicates after server ack.
- **Integration:** WS half-open simulation via `httptest` server that accepts but never reads — agent must reconnect within `read_deadline + 1s`.
- **Integration:** 3-hour offline soak (compressed via fake clock if practical) — assert WAL size stays within limits, ordering preserved, all entries delivered exactly once after reconnect.
- **Manual:** kill -9 the agent in production-like environment, restart, verify dashboard recovers in-progress batch.

## 8. Rollout

Single binary release. No flags, no migration tooling. New agent on existing data dir:

1. Reads any legacy `.wal` files via the back-compat path.
2. New batches use the new `.open` → `.wal` flow.
3. Within one batch window the directory is fully on the new format.

## 9. Open questions / deferred

- **Disk-full alert.** Currently only logged. A future `health` message type could surface this in the dashboard. Tracked for a follow-up; not in this spec.
- **Networkmanager / netlink hook for instant-reconnect on link-up.** OS-specific complexity; backoff with 60 s cap is acceptable. Not in this spec.
