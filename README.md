# Sealbreak

**Created and maintained by [Sergio Rodriguez (SSH-PuR66)](https://github.com/SSH-PuR66).**

[Step through Carbon Copy](https://sergrdz.pages.dev/labs/call-boundary/demos/carbon-copy/) · [Watch Attack Atlas](https://sergrdz.pages.dev/labs/attack-atlas/#sealbreak) · [Read the gate](boundary.py)

[![Sealbreak: an original etched approval seal fractured by a returning grant.](assets/sealbreak-plate.png)](https://sergrdz.pages.dev/labs/call-boundary/demos/carbon-copy/)

Original project artwork generated for Sergio Rodriguez. The illustration is separate from the recorded execution evidence.

Previously published as Countersign. Repository URLs and fixture paths remain stable.
### Attack the gap between an available tool and an approved action

A caller keeps the tool name but swaps the report, changes a nested argument, or replays the request from another process. The fixture baseline accepts every one of the 25 unauthorized proposals. The exact-call gate accepts none of them and preserves all three benign controls.

I built the Python reference gate, the HMAC grant format, the SQLite replay ledger, and the adversarial corpus. An approval binds the actor, execution audience, tool, target, complete arguments, time window, and unused nonce. The output is a decision with inspectable checks.

[Open the experiment](https://sergrdz.pages.dev/labs/call-boundary/) · [Gate implementation](boundary.py) · [Adversarial tests](test_boundary.py) · [Recorded test report](test-report.json)

**Research type:** original controlled authorization experiment. **Execution boundary:** decision-only gate. **Stack:** Python standard library, HMAC-SHA256, SQLite.

## Run it

Python 3.10 or later; standard library only. From this directory:

```sh
python verify.py
```

This runs the test suite, regenerates `vectors.json` and `results.json`, and writes `test-report.json` with the runtime and source hashes. For separate runs:

```sh
python -m unittest -v test_boundary
python fixtures.py
```

## Observed result

The current run passes **105 tests**, including 13 input-ownership and copy-bound regressions, 15 saved-record integrity checks, and 21 evidence-bundle/integration checks. The fixture comparison contains **29 scenarios**:

| Calls in this corpus | Count | Tool-name baseline allows | Approval gate allows |
| --- | ---: | ---: | ---: |
| Unauthorized proposals | 25 | 25 | 0 |
| Benign controls | 3 | 3 | 3 |
| Unavailable-tool negative control | 1 | 0 | 0 |

All 29 gate decisions match their expected reasons. These are curated local fixtures, not a measured attack success rate against an agent, a live-model benchmark, or evidence that arbitrary attacks are prevented. The baseline is intentionally weak: it treats tool availability as sufficient authority. It exists only in `fixtures.py`.

The tests exercise separate processes and threads, including 12 simultaneous thread attempts and eight attempts across four processes. Each same-nonce race produces exactly one accepted decision. Tests also open the ledger in a new interpreter, remove or replace its file, change a nested argument, reorder object keys, and advance the clock between validation and commit.

## The boundary

### Carbon Copy: caller mutation during validation

The original verifier retained the caller's claims dictionary after checking its HMAC. Two deterministic tests failed at commit `42ae08e10603`: a clock callback changed the nonce later written to SQLite, and another extended the expiry after signature verification. This is a local API ownership defect; the tests do not establish remote exploitability or an untrusted clock.

The verifier now takes bounded private JSON snapshots before validation. Subsequent checks and nonce consumption use the same copied values. Copies reject custom object hooks, cycles, excessive breadth/depth, invalid Unicode and oversized encoded input. The two original failures now pass, alongside the existing concurrency and CLI tests.

Run `python snapshot_demo.py` for the actual SQLite decision record, or serve the repository with `python -m http.server 8788 --bind 127.0.0.1` and open `http://127.0.0.1:8788/demos/carbon-copy/`. [Carbon Copy source](snapshot_demo.py) · [recorded result](snapshot-report.json) · [regressions](test_snapshot.py).

`python verify_snapshot_record.py` checks the saved record without executing the gate or rewriting evidence. It rejects changed source hashes, malformed or duplicated JSON fields, inconsistent decisions, and ledger discrepancies. This separation between execution and record inspection draws on the evaluation-stage design of [HarmBench](https://github.com/centerforaisafety/HarmBench); this verifier is original code and copies no upstream implementation. A matching hash establishes consistency with the local source files, not authenticity or proof of execution.

Snapshots make one evaluation internally consistent. They do not make an external executor use that snapshot, and they do not protect a trusted process from arbitrary in-process code.

### Carry the evidence without executing it

`python -B evidence_bundle.py create sealbreak-evidence.zip` packages 19 explicitly named public source, report and demo files with their byte lengths and SHA-256 hashes. Identical inputs produce identical ZIP bytes. `python -B evidence_bundle.py verify sealbreak-evidence.zip` checks the manifest, both saved reports and source consistency entirely in memory, without extraction, execution or regeneration. Creation refuses an existing destination; stale reports must be refreshed explicitly with `python -B verify.py`.

The format rejects compressed/encrypted archives, duplicate or unsafe paths, missing/unexpected members, symlinks, excessive sizes, mismatched headers and failed checksums. It omits local secrets, live grants, SQLite state and illustration assets; this is an evidence bundle, not a self-contained website. [Format and limits](docs/evidence-bundles.md) · [Implementation](evidence_bundle.py) · [Adversarial archive tests](test_evidence_bundle.py).

Carbon Copy now gives each recorded nonce a geometric fingerprint, keeps the original and private copy side by side, and offers step, scrub, play and pause controls. The nonce replacement changes only the caller's shape; the expiry case changes its timestamp while both nonce shapes remain equal. Playback pauses offscreen or in a hidden page; reduced motion keeps manual controls available. [Original virion illustration and prompt](assets/carbon-copy-virion-artwork.md).

```text
Trusted host                                Untrusted proposal
actor + execution audience                  tool + target + args
          |                                           |
          +---- approve exact proposal ----> signed grant
                                                      |
                  strict shape / HMAC / bindings / time
                                                      |
                  SQLite transaction: commit unused nonce
                                                      |
                         decision + inspectable checks
```

`TrustedContext` comes from the host's authentication and routing layer. It must never be reconstructed from model output. `issue_grant` represents the point **after** the host has approved the actual operation; signing is not the approval decision itself.

The envelope has exactly `claims` and `signature`. Claims are:

```json
{
  "version": 1,
  "actor": "analyst:sergio",
  "audience": "portfolio-research-host",
  "tool": "reports.read",
  "target": "report:call-boundary:public",
  "args_sha256": "<64 lowercase hex characters>",
  "issued_at": 1790467200,
  "expires_at": 1790467260,
  "nonce": "<32 lowercase hex characters>"
}
```

HMAC-SHA256 signs a domain-separated, sorted, compact UTF-8 representation of the claims. Verification uses `hmac.compare_digest`. The arguments digest covers the complete arguments object, including nested values. Object ordering is ignored; array ordering, Unicode spelling, booleans, and integers remain distinct. The encoding is project-specific, not an implementation of RFC 8785.

Arguments use a deliberately small JSON subset: objects, arrays, strings, booleans, null, and integers within ±(2^53−1). Floats are rejected. Unknown envelope/proposal/claim fields, duplicate JSON members, boolean timestamps, invalid encodings, excessive nesting, and oversized arguments fail closed. Top-level argument names are tool-specific; any change from the approved arguments changes the digest.

The clock is injected in tests. Approval is valid only when `issued_at <= now < expires_at`, with a maximum 300-second lifetime and no implicit clock-skew allowance. Validity is checked again after SQLite obtains its write lock.

`BEGIN IMMEDIATE` and a primary-key insertion make nonce consumption atomic. The ledger survives process restart. A failed validation does not consume a grant. An accepted decision commits the nonce before returning. The gate refuses a missing, corrupt, or unexpectedly replaced ledger during its lifetime.

## Inspect the evidence

- `boundary.py`: issuer example, verifier, replay ledger, and JSON CLI.
- `fixtures.py`: cases, fixture-only baseline, fresh demonstration key, result generator.
- `test_boundary.py`: adversarial, parser, process, state, and CLI checks.
- `vectors.json`: complete synthetic proposals, trusted contexts, claims, fixture mutations, and expected outcomes.
- `results.json`: actual decisions with nine ordered checks. A `null` check was not evaluated after an earlier rejection.
- `test-report.json`: measured test totals and SHA-256 hashes of the tested source.

Every fixture run generates a fresh signing key and discards it. No demonstration key or valid signed grant is written to the public JSON. Inputs, claims, and expected outcomes are deterministic; the fixture runner reconstructs the signatures locally. The one clearly named `TEST_KEY` in the test file is public test data.

The CLI reads a packet with exactly `proposal` and `grant`; actor and audience are separate host-supplied flags. It exits 0 for an accepted decision and 2 for rejection. An accepted CLI check consumes the grant; it is not a dry run.

```sh
python boundary.py --input request.json --actor analyst:sergio --audience research-host --key-file host.key --ledger approvals.sqlite3
```

`host.key` contains a hexadecimal secret of at least 32 random bytes. The packet must contain a real grant issued for the same host context. The browser exhibit contains a separate, limited Web Crypto demonstration using an ephemeral in-memory key, plus the recorded Python results. It does not possess the host signing key or enforce an execution boundary.

## Integration boundary

This is a local reference gate, not an MCP server, protocol implementation, OAuth provider, or prompt-injection cure. No vulnerable third-party product is identified. It neither evaluates the merits of a requested operation nor knows whether a report's contents changed after approval.

The signing host, authentication context, clock, and local database are trusted. HMAC is symmetric: a verifier holding the key can also issue grants. There is no key rotation, revocation service, distributed ledger, permission UI, or production secret management. A privileged attacker or restored database snapshot can defeat replay history; the in-process identity check is not rollback protection. Nonces are retained indefinitely in this small experiment.

An accepted decision is consumed even if a future executor crashes before acting. This provides at-most-once authorization, not exactly-once external execution. A real integration needs a durable operation identity, reconciliation, and a defined crash-recovery policy. It must execute the same immutable proposal that was checked, keep target resolution within that boundary, and prevent any alternate path around the gate. Those integration properties are not tested here.

## Why this question now

MCP's [2026-07-28 tools specification](https://modelcontextprotocol.io/specification/2026-07-28/server/tools) distinguishes exposed tools from the access controls implementations must enforce, recommends showing inputs for sensitive confirmations, and treats state handles as names whose authorization must be checked on each call. Its [security guidance](https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/security_best_practices) discusses audience validation, explicit scoped consent, and single-use state in their protocol contexts.

Those are motivations for this local experiment. The grant format and measured results here are this project's own; they are not an MCP requirement, conformance test, or vulnerability claim.
