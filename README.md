# tombolo

**Find out if your secrets left the machine — and who carried them out.**

`tombolo` reads Linux `auditd` logs and reconstructs how sensitive data moved
between processes. It is a single Rust binary: ingest, correlate, report.

Its party trick is the case every ancestry-based tool misses.

---

## The problem

Secret data does not usually leave in one clean step. It gets *staged*:

```
  pid 1000   reads ~/.aws/credentials
             writes /tmp/.sysupdate.tar.gz        ← secret is now in a file
                    ⋯ hours pass ⋯
  pid 1100   reads /tmp/.sysupdate.tar.gz          ← picks it up
             writes ~/.cache/upload.bin
             connects to 185.199.108.153:443       ← gone
```

`pid 1100` is a nightly backup job. Its parent is `init`. It shares **no
ancestor** with `pid 1000`.

Every correlator that works by process ancestry looks at that log and reports
**zero flows**. It watches the theft happen and says nothing.

The file is the connection, not the family.

## The name

A **tombolo** is a bar of sand that rises out of the sea and joins an island to
the mainland, permanently. The two landmasses were never connected; the water
between them was the whole story. Then material moves and a bridge forms.

That is exactly the mechanism here. Two unrelated process trees, no shared
ancestry, joined by a file that carried data between them. When `pid 1100` reads
a path that already carries taint, it **adopts** that taint — ancestry is
irrelevant. The reported flow names the *staging file*, because that is the
artifact that actually moved.

---

## What it does

```
raw auditd log ──▶ ingest ──▶ events ──▶ process tree
                                     ├──▶ rules        (10 signals)
                                     ├──▶ taint        (data flow, carrier-aware)
                                     └──▶ escalation   (did the sudo actually work?)
                                              │
                                              ▼
                                        correlation ──▶ terminal / JSON / SARIF / TUI
```

**Ingest.** Decodes raw kernel shorthand: hex fields, `ENRICHED` name fields,
`EXECVE` argv reassembly including split `a1[k]` chunks, `proctitle` fallback.
Multi-record events are stapled by full audit id (`epoch:serial`), never by
record adjacency.

**Process tree.** Builds `pid → ppid` and answers ancestry queries with a hop
cap, so malformed telemetry — a process that is its own parent, a cycle — can
never hang the tool.

**Rules.** Ten independent single-event signals (`LT001`–`LT010`): reverse-shell
primitives, privilege escalation, key access, cloud credential access, raw-IP
egress, persistence writes, anti-forensics, database dumps, archive of sensitive
scope, account creation. Deliberately simple and independent, so all the
intelligence lives in one place — correlation.

**Taint.** Six categories of sensitive data. Any network primitive is an egress
sink (`connect`, `sendto`, `sendmsg`, and `accept` — a reverse shell receives on
an accepted socket). Writing an archive counts as staging.

**Escalation.** `sudo`'s own `execve()` succeeds *before* the password check
happens, so a denied attempt looks like a successful one. The later PAM verdict
is joined under the same pid, and **only the last outcome counts** — so a
typo-then-retry is never permanently marked denied.

**Correlation.** Groups signals and flows into per-incident reports with a
graph-edge view. Ancestry edges render solid; data-flow edges render dashed —
and the dashed edge that crosses between unrelated branches is the whole point.

---

## Getting it right: four things that are easy to get wrong

Each of these is covered by a regression test.

### 1. Syscall numbers are not universal

Syscall `11` is `munmap` on x86-64 and `execve` on aarch64. A flat set that
unions the architectures — `{59, 322, 11, 358, 221, 281}` — therefore claims on
x86-64 that `munmap` (`11`) and `fadvise64` (`221`) are **program executions**.

Alone that looks cosmetic. It is not: a mis-typed `exec` injects a **phantom
process edge** into the tree, the taint engine follows a relationship that never
existed, and the report contains a fabricated connection. A cosmetic bug becomes
a correctness bug the moment something downstream trusts it.

Resolution is now `(architecture, number)` against complete per-architecture
tables generated from the kernel's own `uapi` headers — **375 x86-64, 452 i386,
327 aarch64** (1,154 total). An unknown architecture **refuses to guess**: it can
never be reported as `execve`.

### 2. A recycled pid must not inherit taint

The kernel reuses process ids. If `pid 4242` read a secret an hour ago and an
unrelated, innocent process now runs as `pid 4242`, stale taint would attach to
it — a **false positive that accuses an innocent process**.

A fresh `exec` on a pid clears its taint history. A new program launching is a
new identity.

### 3. A taint-only incident must not be dropped

Incidents are keyed by process-tree root. The most important detection — the
staged pickup — has a sink tree that trips **no rule at all**. It is a backup
job doing backup things.

If incidents are built from *rule findings* and flows merely looked up
afterwards, the confirmed exfiltration is counted in a stats line and then
thrown away. Zero incidents. The tool detects the theft and reports nothing.

Correlation iterates the **union** of finding-roots and flow-roots. A root with
no findings is not noise — it is the headline case.

### 4. Confirmed exfiltration is never "Medium"

If severity is raised one step when several findings share a tree, a
low-severity rule (raw-IP connect) sharing a tree with confirmed data theft
produced **Medium** — the strongest signal the tool can produce, rated
middling. Taint-confirmed flow now floors at **Critical**.

---

## Guards that keep it honest

**Memory on a long tail.** `--window N` (default 200,000) caps retained events;
older ones are evicted and taint state is pruned to pids still present. Carrier
*paths* are kept under their own 4096-entry cap (evicted oldest-first) because a
staged file legitimately outlives the process that wrote it. Taint analysis is
**incremental** — state carries across batches, so cost is linear in the batch,
not the window. A test asserts batched analysis produces identical flows to a
single pass.

**Crashes on hostile input.** An audit log is attacker-influenced: an
unprivileged process controls its own `comm`, its command line, `PATH.name`,
`key` and the `saddr` blob. Fuzzing found a real one — the parser truncated
malformed lines with a **byte** slice, which panics when a multibyte character
straddles the boundary. Trivially reachable DoS, fixed to truncate by
characters. Cumulative fuzzing across the parser, the whole engine, and syscall
resolution: **17.1 M executions, zero crashes**.

**Loud failure.** A detection rule that fails to compile panics at startup
rather than being silently skipped. A security tool that fails silently is worse
than one that does not run.

**Explicit operator intent wins.** `--exclude PATH` overrides the sensitive-path
protection: if you name a path, you meant it.

---

## Usage

```bash
# analyze a log — terminal / JSON / SARIF / TUI
tombolo /var/log/audit/audit.log
tombolo --emit json  /var/log/audit/audit.log
tombolo --emit sarif /var/log/audit/audit.log
tombolo --format tui /var/log/audit/audit.log

# operator table + live tail
tombolo --plain /var/log/audit/audit.log             # aligned event table
tombolo --plain --full --flagged audit.log           # untruncated, dangerous only
tombolo --follow /var/log/audit/audit.log            # live tail, rotation-safe
tombolo --follow --emit json audit.log               # stream incidents as JSON

# noise control
tombolo --include-noise audit.log                    # keep /proc, /sys, loader
tombolo --exclude /opt/noisy audit.log               # extra noise prefix (repeatable)
tombolo --exclude /opt --replace-noise audit.log     # only /opt counts as noise

# normalized JSONL input
tombolo --jsonl events.jsonl
```

**Exit codes:** `2` when incidents are correlated, `0` when clean — so it drops
straight into CI.

`--follow` tolerates `logrotate` (inode change or truncation ⇒ reopen), keeps
parser accumulators between reads so a record split across two polls is still
joined, and ages out builders by feed generation so events emit live instead of
waiting for EOF. `SIGINT`/`SIGTERM` end a tail cleanly and print a final summary:

```
$ tombolo --follow --window 2000 /var/log/audit/audit.log
following /var/log/audit/audit.log — Ctrl-C to stop
retaining up to 2000 events (--window)
follow ended after 0 incident(s); retained 2000 event(s), evicted 2999, 0 carrier(s)
```

TUI keys: `j`/`k` move · `Tab` cycle pane (incidents → graph → detail) · `s`
sessions overlay · `q` quit. The graph pane is layered: solid `└─` for ancestry,
`╌╌▶` for data flow, and a dedicated block for the carrier-mediated hops.

---

## Layout

```
src/ingest.rs         raw audit.log → events (hex, ENRICHED, EXECVE argv)
src/syscall.rs        (arch, nr) resolution
src/syscall_table.rs  GENERATED from kernel headers (1154 syscalls)
src/model.rs          shared event / finding / flow / incident types
src/proctree.rs       process tree + chain rendering
src/rules.rs          LT001–LT010
src/taint.rs          data-flow tracking + carrier adoption
src/escalate.rs       reversible failed-auth annotation
src/correlate.rs      findings + flows → incidents + graph edges
src/lib.rs            pipeline orchestration + streaming session
src/report.rs         terminal / JSON / SARIF 2.1.0
src/plain.rs          --plain table, --follow tailer, auth aggregation
src/tui.rs            ratatui table + graph view
src/jsonl.rs          normalized JSONL input
src/main.rs           CLI
```

Each module is unit-tested; `cargo test` runs the suite.

```
docker run --rm -v "$PWD":/w -w /w rust:1 cargo test
```

**Verified:** 79 tests, clippy clean under `-D warnings`, three fuzz targets at
17.1 M cumulative executions, and the engine checked against real kernel
captures from `linux-audit/audit-userspace` cross-referenced with `ausearch -i`.

---

## Credits

`tombolo` is an independent tool, but its ingest layer and rule/taint engine
began as ports of two excellent projects. Their licences require the notices be
retained, and they deserve the credit:

- **[Hartwell-Labs/labtrace](https://github.com/Hartwell-Labs/labtrace)** — MIT.
  The process tree, the `LT001`–`LT010` rule set, the original taint model and
  the JSON/SARIF reporting surface derive from it.
- **[lab5terr/auditd-log-parser](https://github.com/lab5terr/auditd-log-parser)**
  — 0BSD (Zero-Clause BSD). The raw `audit.log` decoding, `EXECVE` argv rebuild,
  danger heuristics and failed-escalation join derive from it.

Everything in "Getting it right" above is ours: the arch-exact syscall
resolution, carrier-keyed taint adoption, the correlation fixes, the streaming
session, `--window` bounding, and the TUI graph view.

## Licence

MIT — see [LICENSE](LICENSE).
