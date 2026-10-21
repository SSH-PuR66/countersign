"""Create and inspect a bounded public evidence ZIP, never extract or execute it.

The manifest checks byte consistency, not authorship or authenticity. ZIP_STORED
and fixed metadata make identical input files produce identical archive bytes.
"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
from pathlib import Path
import re
import stat
import struct
import zipfile

import verify_snapshot_record as record

ROOT = Path(__file__).resolve().parent
FORMAT = "sealbreak-public-evidence"
MANIFEST = "manifest.json"
SCHEMA_VERSION = 1
MAX_MEMBER_BYTES = 524_288
MAX_TOTAL_BYTES = 3_145_728
MAX_ARCHIVE_BYTES = 4_194_304
FIXED_TIME = (1980, 1, 1, 0, 0, 0)
RUN_SOURCE_NAMES = ("boundary.py", "fixtures.py", "test_boundary.py", "test_snapshot.py",
                    "snapshot_demo.py", "verify_snapshot_record.py", "test_record_integrity.py",
                    "evidence_bundle.py", "test_evidence_bundle.py", "verify.py")
# Never discover files by extension or recursively walk a checkout.
PUBLIC_FILES = tuple(sorted((
    "README.md", "boundary.py", "fixtures.py", "snapshot_demo.py", "verify.py",
    "verify_snapshot_record.py", "evidence_bundle.py", "test_boundary.py",
    "test_snapshot.py", "test_record_integrity.py", "test_evidence_bundle.py",
    "snapshot-report.json", "test-report.json", "results.json", "vectors.json",
    "demos/carbon-copy/index.html", "demos/carbon-copy/carbon-copy.css",
    "demos/carbon-copy/carbon-copy.js", "docs/evidence-bundles.md",
)))


class BundleInvalid(ValueError):
    """An archive or source set violates the evidence format."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise BundleInvalid(message)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def safe_name(name: str) -> bool:
    return (type(name) is str and len(name) <= 160 and
            re.fullmatch(r"[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*", name) is not None and
            all(part not in (".", "..") for part in name.split("/")))


def read_bounded(path: Path, maximum: int, label: str) -> bytes:
    try:
        with path.open("rb") as stream:
            data = stream.read(maximum + 1)
    except OSError as exc:
        raise BundleInvalid(f"{label}: missing or unreadable") from exc
    require(len(data) <= maximum, f"{label}: size limit exceeded")
    return data


def validate_payload(payload: dict[str, bytes]) -> None:
    require(type(payload) is dict and set(payload) == set(PUBLIC_FILES),
            "payload: missing or unexpected public file")
    require(all(type(value) is bytes and len(value) <= MAX_MEMBER_BYTES for value in payload.values()),
            "payload: member size or type invalid")
    require(sum(map(len, payload.values())) <= MAX_TOTAL_BYTES, "payload: total size limit exceeded")
    try:
        saved = record.decode_record(payload["snapshot-report.json"])
        record.validate_record(saved, source_bytes={name: payload[name] for name in record.SOURCE_NAMES})
        run = record.decode_record(payload["test-report.json"])
        require(type(run) is dict and type(run.get("schema_version")) is int and
                run["schema_version"] == 1 and run.get("success") is True,
                "test report: unsupported schema or unsuccessful run")
        require(type(run.get("tests_run")) is int and run["tests_run"] > 0,
                "test report: missing test count")
        for label in ("failures", "errors", "skipped", "fixture_exit_code", "snapshot_exit_code",
                      "record_integrity_exit_code"):
            require(type(run.get(label)) is int and run[label] == 0,
                    f"test report: unsuccessful {label}")
        hashes = run.get("source_sha256")
        record.fields(hashes, set(RUN_SOURCE_NAMES), "test report sources")
        for name in RUN_SOURCE_NAMES:
            require(hashes[name] == sha256(payload[name]), f"test report: SHA-256 mismatch for {name}")
    except record.RecordInvalid as exc:
        raise BundleInvalid(f"snapshot: {exc}") from exc


def collect_public_files(root: Path) -> dict[str, bytes]:
    root = root.resolve()
    payload = {}
    for name in PUBLIC_FILES:
        candidate = root / name
        require(candidate.resolve().is_relative_to(root), f"source: path escapes root: {name}")
        require(not candidate.is_symlink() and candidate.is_file(), f"source: not a regular file: {name}")
        payload[name] = read_bounded(candidate, MAX_MEMBER_BYTES, name)
    validate_payload(payload)
    return payload


def manifest_bytes(payload: dict[str, bytes]) -> bytes:
    manifest = {"format": FORMAT, "schema_version": SCHEMA_VERSION,
                "files": [{"path": name, "size": len(payload[name]), "sha256": sha256(payload[name])}
                          for name in PUBLIC_FILES]}
    return (json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


def encode_bundle(payload: dict[str, bytes]) -> bytes:
    validate_payload(payload)
    contents = {**payload, MANIFEST: manifest_bytes(payload)}
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_STORED, allowZip64=False) as archive:
        for name in sorted(contents):
            entry = zipfile.ZipInfo(name, FIXED_TIME)
            entry.create_system = 3
            entry.external_attr = (stat.S_IFREG | 0o644) << 16
            archive.writestr(entry, contents[name])
    raw = output.getvalue()
    require(len(raw) <= MAX_ARCHIVE_BYTES, "archive: size limit exceeded")
    return raw


def _central_directory_bound(raw: bytes) -> None:
    require(type(raw) is bytes and 22 <= len(raw) <= MAX_ARCHIVE_BYTES,
            "archive: size limit exceeded or empty archive")
    # Limit entry allocation before ZipFile parses the central directory. This
    # version permits no comments, split archives, prepended data or ZIP64.
    signature, disk, central_disk, disk_count, count, size, offset, comment = struct.unpack(
        "<4s4H2LH", raw[-22:])
    require(signature == b"PK\x05\x06" and comment == 0 and disk == central_disk == 0,
            "archive: unsupported end record")
    require(count == disk_count == len(PUBLIC_FILES) + 1, "archive: unexpected entry count")
    require(raw[:4] == b"PK\x03\x04" and offset + size == len(raw) - 22 and
            raw[offset:offset + 4] == b"PK\x01\x02", "archive: invalid directory bounds")
    cursor = offset
    for _ in range(count):
        require(cursor + 46 <= offset + size and raw[cursor:cursor + 4] == b"PK\x01\x02",
                "archive: malformed central directory")
        name_size, extra_size, comment_size = struct.unpack("<3H", raw[cursor + 28:cursor + 34])
        require(1 <= name_size <= 160 and extra_size == comment_size == 0,
                "archive: unsupported central metadata")
        cursor += 46 + name_size
    require(cursor == offset + size, "archive: directory count or size mismatch")


def inspect_bundle_bytes(raw: bytes) -> dict[str, object]:
    _central_directory_bound(raw)
    expected_names = set(PUBLIC_FILES) | {MANIFEST}
    try:
        with zipfile.ZipFile(io.BytesIO(raw), "r", allowZip64=False) as archive:
            entries = archive.infolist()
            names = [entry.filename for entry in entries]
            require(len(entries) == len(expected_names), "archive: unexpected entry count")
            require(len(names) == len(set(names)), "archive: duplicate path")
            require(all(safe_name(entry.orig_filename) and entry.orig_filename == entry.filename
                        for entry in entries), "archive: unsafe path")
            require(set(names) == expected_names, "archive: missing or unexpected public file")
            total = 0
            for entry in entries:
                require(entry.orig_filename == entry.filename and not entry.is_dir(), "archive: unsafe path")
                require(entry.compress_type == zipfile.ZIP_STORED and entry.flag_bits == 0,
                        "archive: compressed or encrypted members are unsupported")
                require(entry.create_system == 3 and stat.S_IFMT(entry.external_attr >> 16) == stat.S_IFREG,
                        "archive: non-regular member")
                require(entry.extra == b"" and entry.comment == b"", "archive: unsupported member metadata")
                require(0 <= entry.file_size <= MAX_MEMBER_BYTES and entry.compress_size == entry.file_size,
                        "archive: invalid member size")
                total += entry.file_size
            require(total <= MAX_TOTAL_BYTES, "archive: total size limit exceeded")
            cursor = 0
            for entry in sorted(entries, key=lambda item: item.header_offset):
                require(entry.header_offset == cursor and cursor + 30 <= len(raw) - 22,
                        "archive: overlapping members or unlisted bytes")
                header = struct.unpack("<4s5H3L2H", raw[cursor:cursor + 30])
                require(header[0] == b"PK\x03\x04" and header[2] == 0 and
                        header[3] == zipfile.ZIP_STORED and header[6] == entry.CRC and
                        header[7] == entry.compress_size and header[8] == entry.file_size and header[10] == 0,
                        "archive: local header disagrees with directory")
                cursor += 30 + header[9] + entry.compress_size
            require(cursor == struct.unpack("<L", raw[-6:-2])[0],
                    "archive: unlisted bytes before directory")
            contents = {}
            for entry in entries:
                with archive.open(entry, "r") as stream:
                    data = stream.read(MAX_MEMBER_BYTES + 1)
                require(len(data) == entry.file_size, "archive: actual member size differs")
                contents[entry.filename] = data
    except (zipfile.BadZipFile, zipfile.LargeZipFile, NotImplementedError, RuntimeError, EOFError) as exc:
        raise BundleInvalid("archive: malformed ZIP or member checksum mismatch") from exc

    try:
        manifest = record.decode_record(contents.pop(MANIFEST))
        record.fields(manifest, {"format", "schema_version", "files"}, "manifest")
        require(manifest["format"] == FORMAT and type(manifest["schema_version"]) is int and
                manifest["schema_version"] == SCHEMA_VERSION, "manifest: unsupported format or schema")
        files = manifest["files"]
        require(type(files) is list and len(files) == len(PUBLIC_FILES), "manifest: invalid file count")
        paths = []
        for entry in files:
            record.fields(entry, {"path", "size", "sha256"}, "manifest.file")
            name = entry["path"]
            require(safe_name(name) and name in contents, "manifest: unsafe or unexpected path")
            paths.append(name)
            require(type(entry["size"]) is int and entry["size"] == len(contents[name]),
                    f"manifest: byte count mismatch for {name}")
            record.hex_string(entry["sha256"], 64, "manifest.sha256")
            require(entry["sha256"] == sha256(contents[name]), f"manifest: SHA-256 mismatch for {name}")
        require(len(set(paths)) == len(PUBLIC_FILES) and set(paths) == set(PUBLIC_FILES),
                "manifest: duplicate or missing file")
    except record.RecordInvalid as exc:
        raise BundleInvalid(f"manifest: {exc}") from exc
    validate_payload(contents)
    return {"passed": True, "verification": "bundle_consistency", "executed": False,
            "extracted": False, "files": len(PUBLIC_FILES), "bytes": len(raw), "sha256": sha256(raw)}


def verify_bundle(path: Path) -> dict[str, object]:
    try:
        return inspect_bundle_bytes(read_bounded(path, MAX_ARCHIVE_BYTES, "archive"))
    except BundleInvalid as exc:
        return {"passed": False, "verification": "bundle_consistency", "executed": False,
                "extracted": False, "error": str(exc)}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subcommands = parser.add_subparsers(dest="command", required=True)
    create = subcommands.add_parser("create", help="Write one new ZIP from the explicit public allowlist")
    create.add_argument("output", type=Path)
    inspect = subcommands.add_parser("verify", help="Read and verify a ZIP without extracting it")
    inspect.add_argument("archive", type=Path)
    args = parser.parse_args(argv)
    if args.command == "verify":
        result = verify_bundle(args.archive)
    else:
        try:
            raw = encode_bundle(collect_public_files(ROOT))
            result = inspect_bundle_bytes(raw)
            # Refuse overwriting any source, report or earlier evidence bundle.
            with args.output.open("xb") as stream:
                stream.write(raw)
            result["created"] = True
        except (BundleInvalid, OSError) as exc:
            result = {"passed": False, "created": False, "executed": False, "error": str(exc)}
    print(json.dumps(result, sort_keys=True))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
