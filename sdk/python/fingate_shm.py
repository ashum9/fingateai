#!/usr/bin/env python3
"""
Phase D8: FinGate Zero-Dependency Python Shared-Memory Strategy SDK (`sdk/python/fingate_shm.py`).

Uses Python stdlib `mmap` + `ctypes` to talk directly to FinGate's POSIX `MAP_SHARED`
ring buffer (`src/ipc/shm_channel.rs`) without JSON, HTTP, or TCP serialization overhead!
"""

import ctypes
import mmap
import os
import struct
import sys
import time

SHM_MAGIC = b"FGSHM001"
SHM_VERSION = 1
SHM_RING_CAP = 256
SHM_RING_MASK = SHM_RING_CAP - 1
SHM_LAYOUT_SIZE = 33088

OFFSET_POD_PID = 20
OFFSET_GATEWAY_KILL_FLAG = 28
OFFSET_POD_HEARTBEAT_TSC = 32
OFFSET_REQ_TAIL = 64
OFFSET_REQ_HEAD = 128
OFFSET_RESP_TAIL = 192
OFFSET_RESP_HEAD = 256
OFFSET_REQ_SLOTS = 320
OFFSET_RESP_SLOTS = 16704

SIDE_BUY = 1
SIDE_SELL = 2

ACTION_NEW = 0
ACTION_REPLACE = 1
ACTION_CANCEL = 2

VERDICT_APPROVED = 0
VERDICT_REJECTED = 1
VERDICT_FILLED = 2
VERDICT_CANCELLED = 3
VERDICT_REPLACED = 4


class NormalizedOrderEvent(ctypes.Structure):
    """Exact 64-byte C-ABI mirror of Rust `NormalizedOrderEvent`."""

    _fields_ = [
        ("cl_ord_id_hash", ctypes.c_uint64),
        ("orig_cl_ord_id_hash", ctypes.c_uint64),
        ("price_ticks", ctypes.c_int64),
        ("qty", ctypes.c_uint64),
        ("algo_id_hash", ctypes.c_uint64),
        ("ingress_tsc", ctypes.c_uint64),
        ("account_slot", ctypes.c_uint16),
        ("symbol_slot", ctypes.c_uint16),
        ("pod_slot", ctypes.c_uint16),
        ("side", ctypes.c_uint8),
        ("action", ctypes.c_uint8),
        ("protocol_id", ctypes.c_uint8),
        ("flags", ctypes.c_uint8),
        ("_pad", ctypes.c_uint8 * 6),
    ]


class ShmOrderVerdict(ctypes.Structure):
    """Exact 64-byte C-ABI mirror of Rust `ShmOrderVerdict`."""

    _fields_ = [
        ("cl_ord_id_hash", ctypes.c_uint64),
        ("wire_seq", ctypes.c_uint64),
        ("leaves_qty", ctypes.c_uint64),
        ("cum_qty", ctypes.c_uint64),
        ("last_px", ctypes.c_int64),
        ("egress_tsc", ctypes.c_uint64),
        ("status", ctypes.c_uint8),
        ("reject_code", ctypes.c_uint8),
        ("_pad", ctypes.c_uint8 * 14),
    ]


assert ctypes.sizeof(NormalizedOrderEvent) == 64, "NormalizedOrderEvent size mismatch"
assert ctypes.sizeof(ShmOrderVerdict) == 64, "ShmOrderVerdict size mismatch"


def fnv1a_64(data: bytes) -> int:
    h = 0xCBF29CE484222325
    for b in data:
        h ^= b
        h = (h * 0x00000100000001B3) & 0xFFFFFFFFFFFFFFFF
    return h


class FinGateShmClient:
    """Zero-copy POSIX shared-memory client for Python trading strategies & AI bots."""

    def __init__(self, shm_path: str):
        self._fd = os.open(shm_path, os.O_RDWR)
        self._mm = mmap.mmap(self._fd, SHM_LAYOUT_SIZE, mmap.MAP_SHARED, mmap.PROT_READ | mmap.PROT_WRITE)
        magic = self._mm[0:8]
        version, cap = struct.unpack_from("<II", self._mm, 8)
        if magic != SHM_MAGIC or version != SHM_VERSION or cap != SHM_RING_CAP:
            self.close()
            raise ValueError(f"Invalid FinGate SHM header: magic={magic!r} version={version} cap={cap}")
        struct.pack_into("<I", self._mm, OFFSET_POD_PID, os.getpid())
        self._usize_fmt = "<Q" if ctypes.sizeof(ctypes.c_size_t) == 8 else "<I"

    def pulse_heartbeat(self) -> None:
        struct.pack_into("<Q", self._mm, OFFSET_POD_HEARTBEAT_TSC, time.monotonic_ns())

    def submit_order(
        self,
        cl_ord_id: str,
        price_ticks: int,
        qty: int,
        side: int = SIDE_BUY,
        action: int = ACTION_NEW,
        account_slot: int = 0,
        symbol_slot: int = 1,
        pod_slot: int = 0,
        algo_id: int = 0,
    ) -> int:
        tail = struct.unpack_from(self._usize_fmt, self._mm, OFFSET_REQ_TAIL)[0]
        head = struct.unpack_from(self._usize_fmt, self._mm, OFFSET_REQ_HEAD)[0]
        if (tail - head) >= SHM_RING_CAP - 1:
            raise BufferError("FinGate SHM request ring full")

        cl_hash = fnv1a_64(cl_ord_id.encode("ascii"))
        ev = NormalizedOrderEvent(
            cl_ord_id_hash=cl_hash,
            orig_cl_ord_id_hash=0,
            price_ticks=price_ticks,
            qty=qty,
            algo_id_hash=algo_id,
            ingress_tsc=time.monotonic_ns(),
            account_slot=account_slot,
            symbol_slot=symbol_slot,
            pod_slot=pod_slot,
            side=side,
            action=action,
            protocol_id=6,
            flags=0,
        )
        slot_offset = OFFSET_REQ_SLOTS + (tail & SHM_RING_MASK) * 64
        self._mm[slot_offset : slot_offset + 64] = bytes(ev)
        struct.pack_into(self._usize_fmt, self._mm, OFFSET_REQ_TAIL, tail + 1)
        return cl_hash

    def poll_verdict(self):
        head = struct.unpack_from(self._usize_fmt, self._mm, OFFSET_RESP_HEAD)[0]
        tail = struct.unpack_from(self._usize_fmt, self._mm, OFFSET_RESP_TAIL)[0]
        if head == tail:
            return None
        slot_offset = OFFSET_RESP_SLOTS + (head & SHM_RING_MASK) * 64
        verdict = ShmOrderVerdict.from_buffer_copy(self._mm[slot_offset : slot_offset + 64])
        struct.pack_into(self._usize_fmt, self._mm, OFFSET_RESP_HEAD, head + 1)
        return verdict

    def wait_verdict(self, timeout_ms: float = 1000.0):
        deadline = time.monotonic() + (timeout_ms / 1000.0)
        while time.monotonic() < deadline:
            v = self.poll_verdict()
            if v is not None:
                return v
        return None

    def close(self) -> None:
        if hasattr(self, "_mm") and self._mm is not None:
            self._mm.close()
            self._mm = None
        if hasattr(self, "_fd") and self._fd is not None:
            os.close(self._fd)
            self._fd = None


def _run_self_test() -> int:
    import tempfile

    with tempfile.NamedTemporaryFile(delete=False) as tf:
        path = tf.name
        tf.write(b"\x00" * SHM_LAYOUT_SIZE)
    try:
        # Initialize header matching Rust MappedShmChannel::create
        with open(path, "r+b") as f:
            mm = mmap.mmap(f.fileno(), SHM_LAYOUT_SIZE)
            mm[0:8] = SHM_MAGIC
            struct.pack_into("<IIH", mm, 8, SHM_VERSION, SHM_RING_CAP, 0)
            mm.close()

        client = FinGateShmClient(path)
        client.pulse_heartbeat()
        cl_hash = client.submit_order("PY-BOT-001", price_ticks=95_000, qty=25, side=SIDE_BUY)
        # Verify order bytes landed at exact offset 320
        raw_ev = NormalizedOrderEvent.from_buffer_copy(client._mm[OFFSET_REQ_SLOTS : OFFSET_REQ_SLOTS + 64])
        assert raw_ev.cl_ord_id_hash == cl_hash
        assert raw_ev.price_ticks == 95_000
        assert raw_ev.qty == 25
        client.close()
        print("OK: FinGate Python SHM SDK ABI (64B event, 64B verdict, 33088B layout) verified.")
        return 0
    finally:
        if os.path.exists(path):
            os.unlink(path)


if __name__ == "__main__":
    if "--self-test" in sys.argv:
        sys.exit(_run_self_test())
    if "--roundtrip" in sys.argv:
        idx = sys.argv.index("--roundtrip")
        shm_path = sys.argv[idx + 1]
        c = FinGateShmClient(shm_path)
        c.pulse_heartbeat()
        cl_h = c.submit_order("PY-LIVE-001", price_ticks=95_000, qty=10, side=SIDE_BUY, account_slot=0, symbol_slot=1)
        v = c.wait_verdict(timeout_ms=2000.0)
        c.close()
        if v is None or v.cl_ord_id_hash != cl_h or v.status != VERDICT_APPROVED:
            print(f"FAIL: verdict={v}", file=sys.stderr)
            sys.exit(1)
        print(f"OK_ROUNDTRIP wire_seq={v.wire_seq} cum_qty={v.cum_qty} status={v.status}")
        sys.exit(0)
    print("Usage: fingate_shm.py --self-test | --roundtrip <shm_path>")
