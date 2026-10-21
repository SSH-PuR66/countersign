# Public evidence bundles

The bundle carries the fixed public source/report/demo allowlist in `evidence_bundle.py`. It does not walk directories or include key files, grant envelopes, SQLite ledgers, binary artifacts, caches, or large illustration assets. It is an evidence bundle, not a self-contained website; the complete repository supplies the demo's illustration. `manifest.json` records every included path, byte length and SHA-256 hash. The archive is uncompressed and uses sorted paths, a fixed 1980 timestamp and fixed file metadata: identical input bytes produce an identical ZIP.

```sh
python -B verify.py
python -B evidence_bundle.py create sealbreak-evidence.zip
python -B evidence_bundle.py verify sealbreak-evidence.zip
```

Creation requires current passing saved reports and refuses an existing destination. It reads public files and writes only the named new archive. Verification reads bytes into bounded memory; it never extracts files, imports bundled Python, executes the gate, or regenerates a report. A missing destination parent must be created explicitly.

The verifier checks archive layout, the exact member set, manifest sizes/hashes, the Carbon Copy decision and ledger invariants, its three original source hashes, and the test report's full source-hash set. Source bytes are passed to the existing saved-record validator in memory. A changed verifier source therefore requires a fresh `verify.py` run before creating a bundle.

Format 1 limits an archive to 4 MiB, each member to 512 KiB, and total member content to 3 MiB. Compressed or encrypted entries, duplicate/unsafe names, symlinks, unexpected files, extra metadata, ZIP64, multipart archives, comments, unlisted bytes, malformed headers and failed checksums are rejected. Uncompressed storage avoids decompression-ratio ambiguity; a compressed archive is outside this format even when benign. The entry count and central directory are bounded before the ZIP reader constructs member objects.

Successful verification establishes consistency with the bundled bytes. It does not authenticate the publisher, prove a run happened, reproduce the test suite, or establish current remote exploitability. A person can alter a report and recompute hashes; compare the final archive digest with a separately trusted release when provenance matters.

Carbon Copy's paired shells are original illustration. Its SVG fingerprints are derived from the recorded nonce bytes, and the timeline changes only when the selected saved state changes. The expiry case deliberately retains equal nonce shapes while highlighting the changed expiry. Playback pauses when hidden or offscreen, and reduced motion leaves manual stepping available.

Primary implementation references: [Python ZIP file API](https://docs.python.org/3/library/zipfile.html) and [binary in-memory streams](https://docs.python.org/3/library/io.html#io.BytesIO). This implementation is original; no third-party archive or evaluation code was copied.
