"""Unit tests for the GDB RSP client. No live Dolphin required."""
from __future__ import annotations

import pytest

from dolphin_re_mcp.gdb.client import (
    ConnectionLost,
    GDBStub,
    GDBStubError,
)


def test_checksum_matches_spike():
    # Two values cross-checked against the original spike packets.
    assert GDBStub._checksum("c") == ord("c") & 0xFF
    assert GDBStub._checksum("Z2,806adac4,4") == sum(b"Z2,806adac4,4") & 0xFF


def test_cmd_roundtrip(stub_with_socket):
    stub, sock = stub_with_socket(["OK"])
    assert stub.cmd("?") == "OK"
    assert sock.sent_payloads == ["?"]


def test_query_supported_sends_expected_payload(stub_with_socket):
    stub, sock = stub_with_socket(["PacketSize=400;swbreak+;hwbreak+"])
    out = stub.query_supported()
    assert "swbreak+" in out
    assert sock.sent_payloads == ["qSupported:multiprocess+;swbreak+;hwbreak+"]


def test_read_registers_decodes_hex(stub_with_socket):
    # 128 bytes worth of hex = 256 hex chars. r0=0xdeadbeef, rest zero.
    blob = "deadbeef" + "00000000" * 31
    stub, _ = stub_with_socket([blob])
    raw = stub.read_registers()
    assert len(raw) == 128
    assert raw[:4] == b"\xde\xad\xbe\xef"


def test_read_register_returns_int(stub_with_socket):
    stub, _ = stub_with_socket(["80004304"])
    assert stub.read_register(0x40) == 0x80004304


def test_read_register_empty_means_unsupported(stub_with_socket):
    stub, _ = stub_with_socket([""])
    assert stub.read_register(0xFF) is None


def test_read_register_error_returns_none(stub_with_socket):
    stub, _ = stub_with_socket(["E01"])
    assert stub.read_register(0xFF) is None


def test_read_mem_decodes_hex(stub_with_socket):
    stub, sock = stub_with_socket(["cafebabe"])
    out = stub.read_mem(0x80000000, 4)
    assert out == b"\xca\xfe\xba\xbe"
    assert sock.sent_payloads == ["m80000000,4"]


def test_read_mem_error_raises(stub_with_socket):
    stub, _ = stub_with_socket(["E0a"])
    with pytest.raises(GDBStubError):
        stub.read_mem(0x80000000, 4)


def test_write_mem_ok(stub_with_socket):
    stub, sock = stub_with_socket(["OK"])
    stub.write_mem(0x80000000, b"\x01\x02\x03\x04")
    assert sock.sent_payloads == ["M80000000,4:01020304"]


def test_write_mem_error_raises(stub_with_socket):
    stub, _ = stub_with_socket(["E03"])
    with pytest.raises(GDBStubError):
        stub.write_mem(0x80000000, b"\x00")


def test_add_write_watchpoint_ok(stub_with_socket):
    stub, sock = stub_with_socket(["OK"])
    assert stub.add_write_watchpoint(0x806ADAC4, 4) == "OK"
    assert sock.sent_payloads == ["Z2,806adac4,4"]


def test_add_write_watchpoint_unsupported(stub_with_socket):
    stub, _ = stub_with_socket([""])
    with pytest.raises(GDBStubError):
        stub.add_write_watchpoint(0x806ADAC4, 4)


def test_add_sw_breakpoint(stub_with_socket):
    stub, sock = stub_with_socket(["OK"])
    stub.add_sw_breakpoint(0x80004304)
    assert sock.sent_payloads == ["Z0,80004304,4"]


def test_continue_async_then_wait(stub_with_socket):
    stub, sock = stub_with_socket([])
    stub.continue_async()
    # Now an unsolicited stop reply arrives.
    sock.queue_unsolicited("T05" + "40:80004304;01:81560000;")
    reply = stub.wait_for_stop()
    assert reply.startswith("T05")
    assert "40:80004304" in reply


def test_step_returns_stop_reply(stub_with_socket):
    stub, _ = stub_with_socket(["T05" + "40:80004308;01:81560000;"])
    out = stub.step()
    assert "40:80004308" in out


def test_interrupt_sends_ctrl_c(stub_with_socket):
    stub, sock = stub_with_socket([])
    stub.interrupt()
    assert sock._send_log[-1] == b"\x03"


def test_is_alive_reflects_socket(stub_with_socket):
    stub, _ = stub_with_socket(["QC0"])
    assert stub.is_alive() is True


def test_socket_closed_raises_connection_lost(stub_with_socket):
    stub, sock = stub_with_socket([])
    sock.close()
    with pytest.raises(ConnectionLost):
        stub.cmd("?")


def test_double_connect_is_noop(stub_with_socket):
    stub, sock = stub_with_socket(["OK"])
    # second connect call (the fixture installs a fake_connect) shouldn't replace socket
    saved = stub.sock
    stub.connect()
    assert stub.sock is saved


def test_oob_stop_reply_during_ack_is_queued(stub_with_socket):
    """
    Reproduces the race seen in the step-4 smoke crash:
      - CPU running with a WP armed.
      - We send `z2,...` and the stub responds `+OK`.
      - But an unrelated stop reply ALSO got queued in the recv stream.
      - Our ack reader sees `$` from that stop reply, not `+`.

    The fix: buffer the OOB packet so the next wait_for_stop returns it,
    and keep reading for our actual ack.
    """
    stub, sock = stub_with_socket([])
    # Manually inject the wire bytes for "$T05...# then +" — a stop reply
    # arrived before our ack from the next sendall.
    # Simulate by pre-queueing the unsolicited packet AND the canned reply
    # to the upcoming z2 send.
    sock.queue_unsolicited("T05" + "40:80004304;01:81560000;")
    sock.queue_reply("OK")
    # Now send the `z2`. The mock framed-ack appears, but the unsolicited
    # T05 arrived first in _recv_buf. The ack consumer should buffer it.
    stub.remove_write_watchpoint(0x806ADAC4, 4)
    # The OOB stop reply should now be retrievable.
    pending = stub.drain_pending_replies()
    assert len(pending) == 1
    assert pending[0].startswith("T05")


def test_read_exact_drains_recv_buf_first(stub_with_socket):
    stub, sock = stub_with_socket([])
    stub._recv_buf = b"xyz"
    out = stub._read_exact(2)
    assert out == b"xy"
    assert stub._recv_buf == b"z"


def test_diag_records_send_and_recv(stub_with_socket):
    stub, _ = stub_with_socket(["OK"])
    stub.cmd("?")
    snap = stub.diag_snapshot()
    # Should see: sent "?" then recv "OK".
    assert len(snap) == 2
    assert snap[0]["dir"] == "sent" and snap[0]["payload"] == "?"
    assert snap[1]["dir"] == "recv" and snap[1]["payload"] == "OK"
    # Latency on the recv should be non-negative; small but non-zero in
    # tests is plausible. Most importantly, it's set.
    assert snap[1]["latency_ms"] >= 0


def test_diag_records_oob_separately(stub_with_socket):
    """OOB stop replies during ack reads should be tagged 'oob', not 'recv'."""
    stub, sock = stub_with_socket([])
    sock.queue_unsolicited("T05" + "40:80004304;01:81560000;")
    sock.queue_reply("OK")
    stub.remove_write_watchpoint(0x806ADAC4, 4)
    snap = stub.diag_snapshot()
    dirs = [e["dir"] for e in snap]
    # We expect: sent z2, oob T05, recv OK
    assert "oob" in dirs
    oob_entry = next(e for e in snap if e["dir"] == "oob")
    assert oob_entry["payload"].startswith("T05")


def test_diag_ring_buffer_caps_at_maxlen(stub_with_socket):
    stub, _ = stub_with_socket(["OK"] * 200)
    # GDBStub default maxlen is 64 — push 100 round trips and confirm cap.
    for _ in range(100):
        stub.cmd("?")
    snap = stub.diag_snapshot()
    assert len(snap) == 64
    # The most recent event should be a recv "OK" at rel_ms == 0.
    assert snap[-1]["payload"] == "OK"
    assert snap[-1]["rel_ms"] == 0


def test_diag_note_records_freeform(stub_with_socket):
    stub, _ = stub_with_socket([])
    stub.record_note("pause_tool start")
    snap = stub.diag_snapshot()
    assert len(snap) == 1
    assert snap[0]["dir"] == "note"
    assert snap[0]["payload"] == "pause_tool start"


def test_diag_snapshot_last_n_trims(stub_with_socket):
    stub, _ = stub_with_socket(["OK"] * 10)
    for _ in range(10):
        stub.cmd("?")
    snap = stub.diag_snapshot(last_n=4)
    assert len(snap) == 4
    # Should be the most-recent 4 entries.
    assert snap[-1]["payload"] == "OK"


def test_probe_responsive_true_on_qC_reply(stub_with_socket):
    stub, sock = stub_with_socket(["QC0"])
    assert stub.probe_responsive(timeout=0.1) is True
    # Probe should have sent exactly one qC packet.
    assert sock.sent_payloads == ["qC"]


def test_probe_responsive_false_on_no_reply(stub_with_socket):
    # No canned replies → mock recv() raises socket.timeout → probe returns False.
    stub, _ = stub_with_socket([])
    assert stub.probe_responsive(timeout=0.05) is False


def test_probe_responsive_false_when_sock_none(stub_with_socket):
    stub, _ = stub_with_socket([])
    stub.sock = None
    assert stub.probe_responsive(timeout=0.05) is False


def test_pending_replies_take_priority_over_wire(stub_with_socket):
    stub, sock = stub_with_socket([])
    # Manually push a pending reply; it should be returned ahead of anything
    # on the wire.
    stub._pending_replies.append("T05fake:1;")
    out = stub._read_packet()
    assert out == "T05fake:1;"
