# pktparsers/tests/tests.py

import json
import time
import socket
import threading
from pathlib import Path
from logging import getLogger
from cli_core.files import iter_from_json
from cli_core.log import setup_logging
from pktparsers import (
    Dissector, 
    apply_filters, 
    get_nested, 
    raw_packet_extractor,
    read,
    write,
    merge_packets,
    read_filters,
    write_filters,
    PacketWriter,
)

logger = getLogger(__name__)

ENABLE_SYSTEM_TESTS = False
INTERACTIVE_MODE    = True
RUN_ALL             = False

# Adjust paths to match your environment
FRAMES_DOT11_RADIO_JSON  = Path("~/Documents/pktparsers/pktparsers/tests/frames_dot11_radio.json").expanduser()
FRAMES_DOT11_RADIO_PCAP  = Path("~/Documents/pktparsers/pktparsers/tests/frames_dot11_radio.pcap").expanduser()
FRAMES_DOT11_RADIO_PCAPNG = Path("~/Documents/pktparsers/pktparsers/tests/frames_dot11_radio.pcapng").expanduser()
FRAMES_DOT11_RADIO_ERF   = Path("~/Documents/pktparsers/pktparsers/tests/frames_dot11_radio.erf").expanduser()

FILTERS_JSON  = Path("/tmp/pktparsers_test_filters.json")
FILTERS_JSONL = Path("/tmp/pktparsers_test_filters.jsonl")

OUTPUT_PCAP   = Path("/tmp/pktparsers_test_out.pcap")
OUTPUT_PCAPNG = Path("/tmp/pktparsers_test_out.pcapng")
OUTPUT_ERF    = Path("/tmp/pktparsers_test_out.erf")
OUTPUT_JSONL  = Path("/tmp/pktparsers_test_out.jsonl")
OUTPUT_JSON   = Path("/tmp/pktparsers_test_out.json")
OUTPUT_MERGED = Path("/tmp/pktparsers_test_merged.pcap")

LIVE_IFACE = "wlan0"  # adjust to your monitor-mode interface
DLT_RADIO  = "DLT_IEEE802_11_RADIO"
DLT_EN10MB = 1

FORMAT_TO_PATH = [
    ("pcap",   OUTPUT_PCAP),
    ("pcapng", OUTPUT_PCAPNG),
    ("erf",    OUTPUT_ERF),
    ("jsonl",  OUTPUT_JSONL),
    ("json",   OUTPUT_JSON),
]

# ---------------------------------------------------------------------------
# Test runner helpers
# ---------------------------------------------------------------------------

def should_run_test(name: str) -> bool:
    global RUN_ALL
    if not INTERACTIVE_MODE or RUN_ALL:
        return True
    choice = input(f"Run test '{name}'? [y/n/a]: ").strip().lower()
    if choice == "a":
        RUN_ALL = True
        return True
    return choice in ("y", "yes")


def run_test(name: str, func, *args, **kwargs):
    if not should_run_test(name):
        logger.info(f"[SKIPPED] {name}")
        return None
    logger.info(f"\n[TEST START] {name}")
    try:
        result = func(*args, **kwargs)
        logger.info(f"[TEST OK] {name} → {result}")
        return result
    except Exception as e:
        logger.error(f"[TEST FAIL] {name}: {e}", exc_info=True)
    finally:
        logger.info(f"[TEST END] {name}\n")


def run_blocking_test(name: str, func, timeout: float = 10, **kwargs):
    if not should_run_test(name):
        logger.info(f"[SKIPPED] {name}")
        return
    logger.info(f"\n[TEST START] {name}")
    stop_event = threading.Event()

    def target():
        try:
            func(timeout=timeout, stop_event=stop_event, **kwargs)
        except Exception as e:
            logger.error(f"[THREAD ERROR] {name}: {e}", exc_info=True)

    thread = threading.Thread(target=target, daemon=True)
    thread.start()
    try:
        thread.join(timeout)
        if thread.is_alive():
            logger.warning(f"[TIMEOUT] {name} exceeded {timeout}s, stopping...")
            stop_event.set()
            thread.join(2)
    except KeyboardInterrupt:
        logger.warning(f"[INTERRUPTED] {name} (Ctrl+C)")
        stop_event.set()
        thread.join(2)
    logger.info(f"[TEST END] {name}\n")


# Dissector tests

def test_dissect_from_json(packets_file: Path, dlt: str | int) -> int:
    """
    Read raw packets from a json/jsonl file via iter_from_json + raw_packet_extractor,
    dissect each one, and log a short excerpt of the result.

    Returns the number of packets successfully dissected.
    """
    with Dissector(dlt) as dissector:
        for _hex, raw in iter_from_json(packets_file, raw_packet_extractor()):
            result = dissector.dissect(raw)
            excerpt = json.dumps(result, default=str)[:160]
            logger.info(f"  [dissect #{dissector.counter}] {excerpt}...")
        logger.info(f"  Dissected {dissector.counter} packet(s) from {packets_file.name}")
    return count

def test_get_nested(parsed: dict):
    """Exercise get_nested against a set of known dot11-radio paths."""
    paths = [
        "rt_hdr.dbm_antenna_signal",
        "rt_hdr.channel.channel",
        "dot11.mac_hdr.fc.type_name",
        "dot11.mac_hdr.sa.addr",
        "dot11.mac_hdr.bssid.addr",
        "dot11.body.fp.beacon_interval",
    ]
    logger.info("  [get_nested] results:")
    for p in paths:
        val = get_nested(p, parsed)
        logger.info(f"    {p:50s} = {val!r}")

def test_apply_filters(parsed: dict):
    """Run a small set of store/display filter pairs against a parsed frame."""
    cases = [
        ("dot11.mac_hdr.fc.type == 0",       "dot11.mac_hdr.fc.type_name"),
        ("rt_hdr.dbm_antenna_signal > -80",  "rt_hdr.dbm_antenna_signal"),
        ("dot11.mac_hdr.fc.type != 99",      "dot11.mac_hdr.sa.addr,dot11.mac_hdr.bssid.addr"),
    ]
    logger.info("  [apply_filters] results:")
    for store_f, display_f in cases:
        store_ok, display = apply_filters(store_f, display_f, parsed)
        logger.info(f"    store='{store_f}' → {store_ok}  |  display='{display_f}' → {display!r}")


def test_dissect_and_filter(packets_file: Path, dlt: str | int):
    """
    Dissect packets from a json/jsonl file and run filter tests against the
    first successfully parsed result.
    """
    first_result = None
    with Dissector(dlt) as dissector:
        for _hex, raw in iter_from_json(packets_file, raw_packet_extractor()):
            first_result = dissector.dissect(raw)
            break

    if first_result is None:
        logger.warning("  No packets found in file — skipping filter tests")
        return

    test_get_nested(first_result)
    test_apply_filters(first_result)


# ---------------------------------------------------------------------------
# IO — read() tests
# ---------------------------------------------------------------------------

def test_read_format(path: Path, dlt: str | int = None, label: str = None) -> int:
    """
    Read any supported format via io.read() and count the yielded results.
    For pcap/pcapng/erf the file must exist; for json/jsonl no dlt is needed.
    """
    label = label or path.suffix.lstrip(".")
    if not path.exists():
        logger.warning(f"  [{label}] file not found, skipping: {path}")
        return 0

    count = 0
    for result in read(path):
        count += 1
        if count == 1:
            excerpt = json.dumps(result, default=str)[:160]
            logger.info(f"  [{label}] first result: {excerpt}...")

    logger.info(f"  [{label}] total results: {count}")
    return count


# ---------------------------------------------------------------------------
# IO — write() / PacketWriter tests
# ---------------------------------------------------------------------------

def test_write_single(packets_file: Path, dlt: str | int):
    """
    Extract raw bytes from a json/jsonl source and write them one at a time
    via io.write() for every binary output format.
    """
    packets: list[bytes] = []
    for _hex, raw in iter_from_json(packets_file, raw_packet_extractor()):
        packets.append(raw)
        if len(packets) >= 5:
            break

    if not packets:
        logger.warning("  No raw packets available for write test")
        return

    dlt_int = dlt if isinstance(dlt, int) else DLT_IEEE802_11_RADIO

    for fmt, out_path in FORMAT_TO_PATH:
        write(packets[0], out_path, fmt=fmt, dlt=dlt_int)
        logger.info(f"  [write single/{fmt}] wrote to {out_path}")


def test_packet_writer(packets_file: Path, dlt: str | int, max_bytes: int = None):
    """
    Write packets incrementally via PacketWriter.
    Tests both the normal case and the max_bytes size cap.
    """
    packets: list[bytes] = []
    for _hex, raw in iter_from_json(packets_file, raw_packet_extractor()):
        packets.append(raw)

    if not packets:
        logger.warning("  No raw packets available for PacketWriter test")
        return

    dlt_int = dlt if isinstance(dlt, int) else DLT_IEEE802_11_RADIO

    for fmt, out_path in FORMAT_TO_PATH:
        written = 0
        with PacketWriter(out_path, fmt=fmt, dlt=dlt_int, max_bytes=max_bytes) as pw:
            for raw in packets:
                if not pw.write({"raw": raw.hex()}):
                    logger.info(f"  [PacketWriter/{fmt}] size cap reached after {written} packet(s)")
                    break
                written += 1

        logger.info(f"  [PacketWriter/{fmt}] wrote {written} packet(s) to {out_path}")

        # Verify the file is readable back through io.read()
        if fmt in ("jsonl", "json") and out_path.exists():
            back = list(read(out_path))
            logger.info(f"  [PacketWriter/{fmt}] read back {len(back)} object(s)")

def test_packet_writer_size_cap(packets_file: Path, dlt: str | int):
    """Dedicated test: verify PacketWriter stops at the given max_bytes limit."""
    # Use a very small cap (1 KB) to trigger the limit quickly
    test_packet_writer(packets_file, dlt, max_bytes=1024)

# ---------------------------------------------------------------------------
# IO — merge_packets() test
# ---------------------------------------------------------------------------

def test_merge_packets(src: Path, dst_format: str = "pcap"):
    """
    Merge a source file into a new file of dst_format via merge_packets().
    Verifies the output is readable.
    """
    if not src.exists():
        logger.warning(f"  [merge] source not found, skipping: {src}")
        return

    merge_packets(src, OUTPUT_MERGED.with_suffix(f".{dst_format}"), dst_format)
    out = OUTPUT_MERGED.with_suffix(f".{dst_format}")
    logger.info(f"  [merge] {src.name} → {out.name}")

    if out.exists() and dst_format in ("jsonl", "json"):
        count = sum(1 for _ in read(out))
        logger.info(f"  [merge] read back {count} object(s)")


# ---------------------------------------------------------------------------
# IO — filter helpers test
# ---------------------------------------------------------------------------

def test_filter_io():
    """
    Exercise write_filters / read_filters round-trip for both .json and .jsonl.
    """
    store_f   = "dot11.mac_hdr.fc.type == 0"
    display_f = "dot11.mac_hdr.sa.addr"

    write_filters(FILTERS_JSON,  simple_path=True,  store_filter=store_f, display_filter=display_f)
    write_filters(FILTERS_JSONL, simple_path=False, store_filter=store_f, display_filter=display_f)

    loaded_json  = read_filters(FILTERS_JSON)
    loaded_jsonl = read_filters(FILTERS_JSONL)

    logger.info(f"  [filter_io] json  round-trip: {loaded_json}")
    logger.info(f"  [filter_io] jsonl round-trip: {loaded_jsonl}")

    assert loaded_json.get("store")   == store_f,   "json store mismatch"
    assert loaded_json.get("display") == display_f, "json display mismatch"
    assert isinstance(loaded_jsonl, list) and loaded_jsonl[0].get("store") == store_f


# ---------------------------------------------------------------------------
# System test — live capture
# ---------------------------------------------------------------------------

def test_live_capture(
    stop_event: threading.Event = None,
    timeout: float = 10,
    store_filter: str = None,
    output_path: Path = None,
    output_fmt: str = "jsonl",
):
    """
    Live capture on a raw AF_PACKET socket, dissect each frame, optionally
    filter and store matches via PacketWriter.

    Requires a monitor-mode interface and root privileges.
    """
    dlt     = DLT_RADIO
    dlt_int = 127
    sock    = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
    sock.bind((LIVE_IFACE, 0))
    sock.settimeout(1.0)

    writer = None
    if output_path:
        writer = PacketWriter(output_path, fmt=output_fmt, dlt=dlt_int).__enter__()

    start = time.time()
    count = stored = 0
    try:
        with Dissector(dlt) as dissector:
            while not (stop_event and stop_event.is_set()):
                if time.time() - start >= timeout:
                    break
                try:
                    raw, _ = sock.recvfrom(65535)
                except socket.timeout:
                    continue

                result = dissector.dissect(raw)
                count += 1

                store_ok, display = apply_filters(store_filter, None, result)
                excerpt = json.dumps(result, default=str)[:120]
                logger.info(f"  [live #{count}] store={store_ok} {excerpt}...")

                if store_ok and writer:
                    if not writer.write(result):
                        logger.info("  [live] output size cap reached, stopping")
                        break
                    stored += 1

    finally:
        sock.close()
        if writer:
            writer.__exit__(None, None, None)
        logger.info(f"  [live] captured={count} stored={stored}")


# ---------------------------------------------------------------------------
# Test suite
# ---------------------------------------------------------------------------

def run_tests():
    # --- Dissector ---
    run_test(
        "dissect packets from json (dot11 radio)",
        test_dissect_from_json,
        FRAMES_DOT11_RADIO_JSON,
        DLT_RADIO,
    )

    run_test(
        "dissect + get_nested + apply_filters (dot11 radio)",
        test_dissect_and_filter,
        FRAMES_DOT11_RADIO_JSON,
        DLT_RADIO,
    )

    # --- io.read() ---
    run_test("read json",   test_read_format, FRAMES_DOT11_RADIO_JSON)
    run_test("read pcap",   test_read_format, FRAMES_DOT11_RADIO_PCAP,   dlt=DLT_RADIO, label="pcap")
    run_test("read pcapng", test_read_format, FRAMES_DOT11_RADIO_PCAPNG, dlt=DLT_RADIO, label="pcapng")
    run_test("read erf",    test_read_format, FRAMES_DOT11_RADIO_ERF,    dlt=DLT_RADIO, label="erf")

    # --- io.write() ---
    run_test(
        "write single packet (all formats)",
        test_write_single,
        FRAMES_DOT11_RADIO_JSON,
        DLT_RADIO,
    )

    # --- PacketWriter ---
    run_test(
        "PacketWriter incremental write (all formats)",
        test_packet_writer,
        FRAMES_DOT11_RADIO_JSON,
        DLT_IEEE802_RADIO,
    )

    run_test(
        "PacketWriter size cap (max_bytes=1024)",
        test_packet_writer_size_cap,
        FRAMES_DOT11_RADIO_JSON,
        DLT_RADIO,
    )

    # --- merge_packets ---
    run_test("merge json → pcap",   test_merge_packets, FRAMES_DOT11_RADIO_JSON,  dst_format="pcap")
    run_test("merge json → jsonl",  test_merge_packets, FRAMES_DOT11_RADIO_JSON,  dst_format="jsonl")
    run_test("merge pcap → jsonl",  test_merge_packets, FRAMES_DOT11_RADIO_PCAP,  dst_format="jsonl")

    # --- filter IO helpers ---
    run_test("filter write/read round-trip", test_filter_io)

    if ENABLE_SYSTEM_TESTS:
        logger.warning("SYSTEM TESTS ENABLED — requires monitor interface and root")
        run_blocking_test(
            "live capture 10s (no filter, no output)",
            test_live_capture,
            timeout=10,
        )
        run_blocking_test(
            "live capture 10s (store beacon frames → jsonl)",
            test_live_capture,
            timeout=10,
            store_filter="dot11.mac_hdr.fc.type == 0",
            output_path=Path("/tmp/pktparsers_live_beacons.jsonl"),
            output_fmt="jsonl",
        )
    else:
        logger.info("System tests disabled (set ENABLE_SYSTEM_TESTS = True to enable)")


def main():
    setup_logging(verbose=True, output_fullpath="/tmp/pktparsers_tests.log")
    run_tests()


if __name__ == "__main__":
    main()
