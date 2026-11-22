/*
 * FinGate Session Shield — Zero-Copy C11 ABI & POSIX Shared Memory Header
 * Phase D8: Polyglot C / C++ / Go (cgo) / Python (ctypes) Interface
 *
 * Byte-exact mirror of:
 *   - src/protocol/mod.rs::NormalizedOrderEvent (64 bytes, 64-byte aligned)
 *   - src/ipc/shm_channel.rs::ShmOrderVerdict   (64 bytes, 64-byte aligned)
 *   - src/ipc/shm_channel.rs::ShmChannelLayout  (33088 bytes, 5 isolated cache lines + 2x256 rings)
 */

#ifndef FINGATE_H
#define FINGATE_H

#include <stdalign.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define FINGATE_ABI_VERSION      0x00010800u
#define FINGATE_SHM_MAGIC        "FGSHM001"
#define FINGATE_SHM_VERSION      1u
#define FINGATE_SHM_RING_CAP     256u
#define FINGATE_SHM_RING_MASK    (FINGATE_SHM_RING_CAP - 1u)

/* Protocol identifiers */
#define FINGATE_PROTO_FIX44      1u
#define FINGATE_PROTO_SBE_ILINK3 2u
#define FINGATE_PROTO_OUCH5      3u
#define FINGATE_PROTO_BOE3       4u
#define FINGATE_PROTO_NSE_TRIM   5u
#define FINGATE_PROTO_FAST_JSON  6u

/* Side & action codes */
#define FINGATE_SIDE_BUY         1u
#define FINGATE_SIDE_SELL        2u

#define FINGATE_ACTION_NEW        0u
#define FINGATE_ACTION_REPLACE    1u
#define FINGATE_ACTION_CANCEL     2u
#define FINGATE_ACTION_MASSCANCEL 3u

/* Verdict status codes */
#define FINGATE_VERDICT_APPROVED  0u
#define FINGATE_VERDICT_REJECTED  1u
#define FINGATE_VERDICT_FILLED    2u
#define FINGATE_VERDICT_CANCELLED 3u
#define FINGATE_VERDICT_REPLACED  4u

#ifdef __cplusplus
#define FINGATE_ALIGN64 alignas(64)
#define FINGATE_ALIGN128 alignas(128)
#else
#define FINGATE_ALIGN64 _Alignas(64)
#define FINGATE_ALIGN128 _Alignas(128)
#endif

typedef struct fingate_order_event {
    FINGATE_ALIGN64 uint64_t cl_ord_id_hash;      /* 0..8   */
    uint64_t orig_cl_ord_id_hash; /* 8..16  */
    int64_t  price_ticks;         /* 16..24 */
    uint64_t qty;                 /* 24..32 */
    uint64_t algo_id_hash;        /* 32..40 */
    uint64_t ingress_tsc;         /* 40..48 */
    uint16_t account_slot;        /* 48..50 */
    uint16_t symbol_slot;         /* 50..52 */
    uint16_t pod_slot;            /* 52..54 */
    uint8_t  side;                /* 54     */
    uint8_t  action;              /* 55     */
    uint8_t  protocol_id;         /* 56     */
    uint8_t  flags;               /* 57     */
    uint8_t  _pad[6];             /* 58..64 */
} fingate_order_event_t;

typedef struct fingate_order_verdict {
    FINGATE_ALIGN64 uint64_t cl_ord_id_hash;      /* 0..8   */
    uint64_t wire_seq;            /* 8..16  */
    uint64_t leaves_qty;          /* 16..24 */
    uint64_t cum_qty;             /* 24..32 */
    int64_t  last_px;             /* 32..40 */
    uint64_t egress_tsc;          /* 40..48 */
    uint8_t  status;              /* 48     */
    uint8_t  reject_code;         /* 49     */
    uint8_t  _pad[14];            /* 50..64 */
} fingate_order_verdict_t;

typedef struct fingate_cacheline_usize {
    FINGATE_ALIGN64 size_t val;
    uint8_t _pad[64 - sizeof(size_t)];
} fingate_cacheline_usize_t;

typedef struct fingate_shm_layout {
    /* Cache line 0 (0..64): Metadata & liveness */
    FINGATE_ALIGN64 uint8_t magic[8];
    uint32_t version;
    uint32_t ring_capacity;
    uint16_t pod_slot;
    uint16_t _pad0;
    uint32_t pod_pid;
    uint32_t gateway_pid;
    uint32_t gateway_kill_flag;
    uint64_t pod_heartbeat_tsc;
    uint8_t  _pad_line0[24];

    /* Cache lines 1..4 (64..320): Isolated atomic ring cursors */
    fingate_cacheline_usize_t req_tail;
    fingate_cacheline_usize_t req_head;
    fingate_cacheline_usize_t resp_tail;
    fingate_cacheline_usize_t resp_head;

    /* Arena (320..33088) */
    fingate_order_event_t   req_slots[FINGATE_SHM_RING_CAP];
    fingate_order_verdict_t resp_slots[FINGATE_SHM_RING_CAP];
} fingate_shm_layout_t;

#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L
_Static_assert(sizeof(fingate_order_event_t) == 64, "NormalizedOrderEvent must be 64 bytes");
_Static_assert(sizeof(fingate_order_verdict_t) == 64, "ShmOrderVerdict must be 64 bytes");
_Static_assert(offsetof(fingate_shm_layout_t, req_tail) == 64, "req_tail offset must be 64");
_Static_assert(offsetof(fingate_shm_layout_t, req_head) == 128, "req_head offset must be 128");
_Static_assert(offsetof(fingate_shm_layout_t, resp_tail) == 192, "resp_tail offset must be 192");
_Static_assert(offsetof(fingate_shm_layout_t, resp_head) == 256, "resp_head offset must be 256");
_Static_assert(offsetof(fingate_shm_layout_t, req_slots) == 320, "req_slots offset must be 320");
_Static_assert(offsetof(fingate_shm_layout_t, resp_slots) == 16704, "resp_slots offset must be 16704");
_Static_assert(sizeof(fingate_shm_layout_t) == 33088, "ShmChannelLayout must be 33088 bytes");
#endif

typedef struct FinGateShmHandle FinGateShmHandle;
typedef struct FinGateStampedShmHandle FinGateStampedShmHandle;

/* Track I6: 128B Single-MESI Sequence-Stamped SHM Ring (`FGSHM002`) */
#define FINGATE_STAMPED_SHM_MAGIC "FGSHM002"

typedef struct fingate_stamped_req_slot {
    FINGATE_ALIGN128 uint64_t seq_stamp;
    uint8_t _pad[56];
    fingate_order_event_t payload;
} fingate_stamped_req_slot_t;

typedef struct fingate_stamped_resp_slot {
    FINGATE_ALIGN128 uint64_t seq_stamp;
    uint8_t _pad[56];
    fingate_order_verdict_t payload;
} fingate_stamped_resp_slot_t;

typedef struct fingate_stamped_shm_layout {
    FINGATE_ALIGN128 uint8_t magic[8];
    uint32_t version;
    uint32_t ring_capacity;
    uint16_t pod_slot;
    uint16_t _pad0;
    uint32_t pod_pid;
    uint32_t gateway_pid;
    uint32_t gateway_kill_flag;
    uint64_t pod_heartbeat_tsc;
    uint8_t  _pad_hdr[88];
    FINGATE_ALIGN128 uint64_t req_head;
    uint8_t  _pad_req_head[120];
    FINGATE_ALIGN128 uint64_t resp_head;
    uint8_t  _pad_resp_head[120];
    fingate_stamped_req_slot_t  req_slots[FINGATE_SHM_RING_CAP];
    fingate_stamped_resp_slot_t resp_slots[FINGATE_SHM_RING_CAP];
} fingate_stamped_shm_layout_t;

#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L
_Static_assert(sizeof(fingate_stamped_req_slot_t) == 128, "StampedReqSlot must be 128 bytes");
_Static_assert(sizeof(fingate_stamped_resp_slot_t) == 128, "StampedRespSlot must be 128 bytes");
_Static_assert(offsetof(fingate_stamped_shm_layout_t, req_head) == 128, "stamped req_head offset must be 128");
_Static_assert(offsetof(fingate_stamped_shm_layout_t, resp_head) == 256, "stamped resp_head offset must be 256");
_Static_assert(offsetof(fingate_stamped_shm_layout_t, req_slots) == 384, "stamped req_slots offset must be 384");
#endif

uint32_t fingate_abi_version(void);
int fingate_sha256_hw_accelerated(void);
FinGateShmHandle *fingate_shm_connect(const char *path);
FinGateShmHandle *fingate_shm_create(const char *path, uint16_t pod_slot);
int fingate_shm_submit_order(FinGateShmHandle *handle, const fingate_order_event_t *order);
int fingate_shm_poll_verdict(FinGateShmHandle *handle, fingate_order_verdict_t *out_verdict);
void fingate_shm_pulse_heartbeat(FinGateShmHandle *handle, uint64_t tsc_ns);
void fingate_shm_close(FinGateShmHandle *handle);
FinGateStampedShmHandle *fingate_stamped_shm_create(const char *path, uint16_t pod_slot);
FinGateStampedShmHandle *fingate_stamped_shm_open(const char *path);
void fingate_stamped_shm_close(FinGateStampedShmHandle *handle);

#ifdef __cplusplus
}
#endif

#endif /* FINGATE_H */
