//! Month 4 / Phase C1: Lock-Free Shared-Nothing Async TCP Ingress Listener (`SessionShieldTcpServer`).
//!
//! Phase C1 Upgrades:
//! 1. `LockFreeSessionShieldServer`: dedicated pinned OS worker thread (`fingate-core-0`) owning
//!    exclusive `&mut` references to `FastClOrdIdRouter`, `PreTradeRiskEngine`, and `WriteAheadLog`
//!    — eliminating all `Arc<tokio::sync::Mutex<...>>` contention on the hot order path.
//! 2. Per-connection wait-free cache-padded `SpscRing` request/response pairs (`src/ring.rs`).
//! 3. Zero-syscall `HardwareTscClock::global().now_nanos()` replacing `SystemTime::now()`.
//! 4. Stack-allocated ASCII `EXEC-xxxxxxx` formatter eliminating heap `format!()` on every fill.
//! 5. Retains `SessionShieldTcpServer::bind` compatibility for existing integration suites.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use anyhow::Result;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Mutex, Notify};

use crate::admin::control::ControlPlaneState;
use crate::env::HardwareTscClock;
use crate::fix::wire::{FixFrameBuilder, FixTcpDefragmenter, FixWireView};
use crate::ipc::shm_channel::{MappedShmChannel, ShmOrderVerdict, VERDICT_APPROVED, VERDICT_REJECTED};
use crate::protocol::SIDE_BUY;
use crate::ring::{SpscConsumer, SpscProducer, SpscRing};
use crate::risk::engine::PreTradeRiskEngine;
use crate::shield::multiplexer::{FastClOrdIdRouter, FixedWireId, StrategyPodMultiplexer};
use crate::wal::WriteAheadLog;

/// Format `EXEC-<seq>` directly into a stack byte array (0 heap allocations).
#[inline(always)]
fn format_exec_id(seq: u64, buf: &mut [u8; 24]) -> &str {
    buf[0..5].copy_from_slice(b"EXEC-");
    let mut tmp = [0u8; 20];
    let mut n = seq;
    let mut pos = 20;
    if n == 0 {
        pos -= 1;
        tmp[pos] = b'0';
    } else {
        while n > 0 {
            pos -= 1;
            tmp[pos] = b'0' + (n % 10) as u8;
            n /= 10;
        }
    }
    let digits = 20 - pos;
    buf[5..5 + digits].copy_from_slice(&tmp[pos..20]);
    unsafe { std::str::from_utf8_unchecked(&buf[..5 + digits]) }
}

/// Request pushed lock-free from a TCP reader task to the pinned core worker thread.
pub struct CoreOrderCommand {
    pub cl_ord_id_hash: u64,
    pub pod_slot: u16,
    pub account_slot: usize,
    pub symbol_id: u32,
    pub is_buy: bool,
    pub price: u64,
    pub qty: u64,
    pub in_seq: u64,
    pub now_ns: u64,
}

/// Verdict returned lock-free from the pinned core worker thread to the TCP writer task.
pub enum CoreOrderVerdict {
    Approved { wire_id: FixedWireId },
    Rejected,
}

struct RegisteredConnRing {
    req_rx: SpscConsumer<CoreOrderCommand, 1024>,
    resp_tx: SpscProducer<CoreOrderVerdict, 1024>,
    closed: Arc<AtomicBool>,
}

/// Phase C1 / D1: Lock-Free Shared-Nothing Session Shield Server (`0` hot-path Mutexes).
/// Polls both per-connection TCP SPSC rings AND cross-process POSIX `MappedShmChannel` rings.
pub struct LockFreeSessionShieldServer {
    pub local_addr: SocketAddr,
    listener: TcpListener,
    register_tx: std::sync::mpsc::Sender<RegisteredConnRing>,
    shm_register_tx: std::sync::mpsc::Sender<Arc<MappedShmChannel>>,
    shutdown: Arc<Notify>,
    running: Arc<AtomicBool>,
    control_plane: Option<Arc<ControlPlaneState>>,
}

impl LockFreeSessionShieldServer {
    /// Bind an async TCP listener backed by a dedicated, mutex-free pinned Core Worker OS thread.
    pub async fn bind(
        addr: &str,
        gateway_prefix: &str,
        mut risk: PreTradeRiskEngine,
        mut wal: Option<WriteAheadLog>,
        control_plane: Option<Arc<ControlPlaneState>>,
    ) -> Result<Self> {
        let listener = TcpListener::bind(addr).await?;
        let local_addr = listener.local_addr()?;
        let (register_tx, register_rx) = std::sync::mpsc::channel::<RegisteredConnRing>();
        let (shm_register_tx, shm_register_rx) =
            std::sync::mpsc::channel::<Arc<MappedShmChannel>>();
        let running = Arc::new(AtomicBool::new(true));
        let running_worker = running.clone();
        let cp_worker = control_plane.clone();
        let mut router = FastClOrdIdRouter::new(gateway_prefix);

        // Spawn dedicated shared-nothing core thread: owns exclusive `&mut` Risk, Router & WAL.
        std::thread::Builder::new()
            .name("fingate-core-0".to_string())
            .spawn(move || {
                let _ = crate::sys::pin_current_thread_to_core(2);
                let mut conns: Vec<RegisteredConnRing> = Vec::with_capacity(64);
                let mut shm_channels: Vec<Arc<MappedShmChannel>> = Vec::with_capacity(16);
                let mut wal_payload = [0u8; 64];
                let mut shm_seq = 1u64;

                while running_worker.load(Ordering::Relaxed) {
                    // Drain any newly accepted TCP connections (control path only)
                    while let Ok(new_conn) = register_rx.try_recv() {
                        conns.push(new_conn);
                    }
                    // Drain any newly attached SHM pod channels (Phase D1)
                    while let Ok(shm) = shm_register_rx.try_recv() {
                        shm_channels.push(shm);
                    }

                    let mut did_work = false;

                    // Phase D1: Poll zero-copy POSIX SHM channels directly on core thread (< 300 ns RTT)
                    for shm in &shm_channels {
                        while let Some(order) = shm.gateway_try_poll_order() {
                            did_work = true;
                            let now_ns = HardwareTscClock::global().now_nanos();
                            let kill_active = cp_worker
                                .as_ref()
                                .map(|cp| cp.kill_switch_active.load(Ordering::Relaxed))
                                .unwrap_or(false)
                                || shm.layout().gateway_kill_flag.load(Ordering::Relaxed) != 0;

                            let verdict = if kill_active {
                                ShmOrderVerdict {
                                    cl_ord_id_hash: order.cl_ord_id_hash,
                                    wire_seq: 0,
                                    leaves_qty: 0,
                                    cum_qty: 0,
                                    last_px: order.price_ticks,
                                    egress_tsc: now_ns,
                                    status: VERDICT_REJECTED,
                                    reject_code: 99,
                                    _pad: [0; 14],
                                }
                            } else {
                                let is_buy = order.side == SIDE_BUY;
                                let price_u64 = order.price_ticks.max(0) as u64;
                                match risk.check_order_slot(
                                    order.account_slot as usize,
                                    order.cl_ord_id_hash,
                                    order.symbol_slot as u32,
                                    is_buy,
                                    price_u64,
                                    order.qty,
                                    now_ns,
                                ) {
                                    Ok(()) => {
                                        let wire_id = router.register_outbound_fast(
                                            order.pod_slot,
                                            order.cl_ord_id_hash,
                                            order.qty,
                                            price_u64,
                                            is_buy,
                                            now_ns / 1_000_000,
                                        );
                                        let _ = router.route_inbound_fill_fast(wire_id.wire_seq, order.qty);
                                        if let Some(ref mut log) = wal {
                                            wal_payload[0..8].copy_from_slice(&order.cl_ord_id_hash.to_le_bytes());
                                            wal_payload[8..16].copy_from_slice(&price_u64.to_le_bytes());
                                            wal_payload[16..24].copy_from_slice(&order.qty.to_le_bytes());
                                            let _ = log.append(shm_seq, now_ns, 0, &wal_payload[..24]);
                                            shm_seq += 1;
                                        }
                                        ShmOrderVerdict {
                                            cl_ord_id_hash: order.cl_ord_id_hash,
                                            wire_seq: wire_id.wire_seq,
                                            leaves_qty: 0,
                                            cum_qty: order.qty,
                                            last_px: order.price_ticks,
                                            egress_tsc: HardwareTscClock::global().now_nanos(),
                                            status: VERDICT_APPROVED,
                                            reject_code: 0,
                                            _pad: [0; 14],
                                        }
                                    }
                                    Err(_) => ShmOrderVerdict {
                                        cl_ord_id_hash: order.cl_ord_id_hash,
                                        wire_seq: 0,
                                        leaves_qty: 0,
                                        cum_qty: 0,
                                        last_px: order.price_ticks,
                                        egress_tsc: HardwareTscClock::global().now_nanos(),
                                        status: VERDICT_REJECTED,
                                        reject_code: 1,
                                        _pad: [0; 14],
                                    },
                                }
                            };

                            let mut pending = verdict;
                            loop {
                                match shm.gateway_try_publish_verdict(pending) {
                                    Ok(()) => break,
                                    Err(v) => {
                                        pending = v;
                                        std::hint::spin_loop();
                                    }
                                }
                            }
                        }
                    }

                    let mut i = 0;
                    while i < conns.len() {
                        let conn = &mut conns[i];
                        while let Some(cmd) = conn.req_rx.try_pop() {
                            did_work = true;
                            let kill_active = cp_worker
                                .as_ref()
                                .map(|cp| cp.kill_switch_active.load(Ordering::Relaxed))
                                .unwrap_or(false);

                            let verdict = if kill_active {
                                CoreOrderVerdict::Rejected
                            } else {
                                match risk.check_order_slot(
                                    cmd.account_slot,
                                    cmd.cl_ord_id_hash,
                                    cmd.symbol_id,
                                    cmd.is_buy,
                                    cmd.price,
                                    cmd.qty,
                                    cmd.now_ns,
                                ) {
                                    Ok(()) => {
                                        let wire_id = router.register_outbound_fast(
                                            cmd.pod_slot,
                                            cmd.cl_ord_id_hash,
                                            cmd.qty,
                                            cmd.price,
                                            cmd.is_buy,
                                            cmd.now_ns / 1_000_000,
                                        );
                                        let _ = router.route_inbound_fill_fast(wire_id.wire_seq, cmd.qty);
                                        if let Some(ref mut log) = wal {
                                            wal_payload[0..8].copy_from_slice(&cmd.cl_ord_id_hash.to_le_bytes());
                                            wal_payload[8..16].copy_from_slice(&cmd.price.to_le_bytes());
                                            wal_payload[16..24].copy_from_slice(&cmd.qty.to_le_bytes());
                                            let _ = log.append(cmd.in_seq, cmd.now_ns, 0, &wal_payload[..24]);
                                        }
                                        if let Some(ref cp) = cp_worker {
                                            cp.wal_synced_seq.store(cmd.in_seq, Ordering::Relaxed);
                                        }
                                        CoreOrderVerdict::Approved { wire_id }
                                    }
                                    Err(_) => CoreOrderVerdict::Rejected,
                                }
                            };

                            // Spin-push response into wait-free SPSC return ring
                            let mut pending = verdict;
                            loop {
                                match conn.resp_tx.try_push(pending) {
                                    Ok(()) => break,
                                    Err(v) => {
                                        pending = v;
                                        std::hint::spin_loop();
                                    }
                                }
                            }
                        }

                        if conn.closed.load(Ordering::Acquire) {
                            conns.swap_remove(i);
                        } else {
                            i += 1;
                        }
                    }

                    if !did_work {
                        if shm_channels.is_empty() {
                            std::thread::yield_now();
                        } else {
                            std::hint::spin_loop();
                        }
                    }
                }
            })?;

        Ok(Self {
            local_addr,
            listener,
            register_tx,
            shm_register_tx,
            shutdown: Arc::new(Notify::new()),
            running,
            control_plane,
        })
    }

    /// Phase D1: Attach a zero-copy POSIX SHM channel directly to the `fingate-core-0` worker loop.
    pub fn attach_shm_channel(&self, channel: Arc<MappedShmChannel>) -> Result<()> {
        self.shm_register_tx
            .send(channel)
            .map_err(|_| anyhow::anyhow!("fingate-core-0 worker shut down"))
    }

    pub fn shutdown(&self) {
        self.running.store(false, Ordering::Release);
        self.shutdown.notify_waiters();
    }

    pub async fn run(&self) -> Result<()> {
        let shutdown = self.shutdown.clone();
        loop {
            tokio::select! {
                _ = shutdown.notified() => break,
                accept_res = self.listener.accept() => {
                    let (socket, _) = match accept_res {
                        Ok(conn) => conn,
                        Err(e) => {
                            tracing::warn!("LockFree TCP accept error: {:?}", e);
                            continue;
                        }
                    };
                    let _ = socket.set_nodelay(true);
                    let (req_tx, req_rx) = SpscRing::<CoreOrderCommand, 1024>::split();
                    let (resp_tx, resp_rx) = SpscRing::<CoreOrderVerdict, 1024>::split();
                    let closed = Arc::new(AtomicBool::new(false));
                    if self.register_tx.send(RegisteredConnRing {
                        req_rx,
                        resp_tx,
                        closed: closed.clone(),
                    }).is_err() {
                        break;
                    }
                    let shutdown_child = shutdown.clone();
                    let cp_child = self.control_plane.clone();
                    tokio::spawn(async move {
                        let _ = Self::handle_connection_lock_free(
                            socket,
                            req_tx,
                            resp_rx,
                            closed,
                            shutdown_child,
                            cp_child,
                        ).await;
                    });
                }
            }
        }
        Ok(())
    }

    async fn handle_connection_lock_free(
        mut stream: TcpStream,
        mut req_tx: SpscProducer<CoreOrderCommand, 1024>,
        mut resp_rx: SpscConsumer<CoreOrderVerdict, 1024>,
        closed: Arc<AtomicBool>,
        shutdown: Arc<Notify>,
        control_plane: Option<Arc<ControlPlaneState>>,
    ) -> Result<()> {
        let mut defragmenter = FixTcpDefragmenter::new();
        let mut read_buf = [0u8; 8192];
        let mut exec_id_buf = [0u8; 24];
        let mut out_seq = 1u64;
        let clock = HardwareTscClock::global();

        loop {
            tokio::select! {
                _ = shutdown.notified() => break,
                read_res = stream.read(&mut read_buf) => {
                    let n = match read_res {
                        Ok(0) | Err(_) => break,
                        Ok(n) => n,
                    };

                    let raw_frames = defragmenter.feed(&read_buf[..n]);
                    for raw_frame in raw_frames {
                        let view = match FixWireView::parse_and_validate(&raw_frame) {
                            Ok(v) => v,
                            Err(_) => continue,
                        };
                        let msg_type = match view.msg_type() {
                            Some(t) => t,
                            None => continue,
                        };

                        match msg_type {
                            "A" => {
                                let sender = view.get_str(49).unwrap_or("STRAT");
                                let mut builder = FixFrameBuilder::new();
                                builder.push_str(35, "A");
                                builder.push_u64(34, out_seq);
                                out_seq += 1;
                                builder.push_str(49, "FINGATE");
                                builder.push_str(56, sender);
                                builder.push_u64(108, 30);
                                let resp = builder.finish_soh_bytes(false, false);
                                if stream.write_all(&resp).await.is_err() {
                                    closed.store(true, Ordering::Release);
                                    return Ok(());
                                }
                            }
                            "0" => {
                                let sender = view.get_str(49).unwrap_or("STRAT");
                                let mut builder = FixFrameBuilder::new();
                                builder.push_str(35, "0");
                                builder.push_u64(34, out_seq);
                                out_seq += 1;
                                builder.push_str(49, "FINGATE");
                                builder.push_str(56, sender);
                                let resp = builder.finish_soh_bytes(false, false);
                                if stream.write_all(&resp).await.is_err() {
                                    closed.store(true, Ordering::Release);
                                    return Ok(());
                                }
                            }
                            "D" => {
                                let cl_ord_id = view.get_str(11).unwrap_or("ORD-UNKNOWN");
                                let symbol = view.get_str(55).unwrap_or("BTC-USDT");
                                let side = view.get_str(54).unwrap_or("1");
                                let is_buy = side == "1";
                                let qty = view.get_u64(38).unwrap_or(1);
                                let price = view.get_u64(44).unwrap_or(95000);
                                let sender = view.get_str(49).unwrap_or("STRAT");
                                let in_seq = view.msg_seq_num().unwrap_or(1);
                                let now_ns = clock.now_nanos();

                                if let Some(ref cp) = control_plane {
                                    if let Ok(s) = std::str::from_utf8(&raw_frame) {
                                        cp.record_wire_frame(s);
                                    }
                                }

                                let mut pending = CoreOrderCommand {
                                    cl_ord_id_hash: in_seq,
                                    pod_slot: 1,
                                    account_slot: 0,
                                    symbol_id: 1,
                                    is_buy,
                                    price,
                                    qty,
                                    in_seq,
                                    now_ns,
                                };
                                loop {
                                    match req_tx.try_push(pending) {
                                        Ok(()) => break,
                                        Err(cmd) => {
                                            pending = cmd;
                                            std::hint::spin_loop();
                                        }
                                    }
                                }

                                // Wait-free spin/yield for core worker verdict (sub-microsecond)
                                let verdict = loop {
                                    if let Some(v) = resp_rx.try_pop() {
                                        break v;
                                    }
                                    std::hint::spin_loop();
                                };

                                match verdict {
                                    CoreOrderVerdict::Approved { wire_id } => {
                                        let mut builder = FixFrameBuilder::new();
                                        builder.push_str(35, "8");
                                        builder.push_u64(34, out_seq);
                                        out_seq += 1;
                                        builder.push_str(49, "FINGATE");
                                        builder.push_str(56, sender);
                                        builder.push_str(37, wire_id.as_str());
                                        builder.push_str(11, cl_ord_id);
                                        builder.push_str(17, format_exec_id(out_seq, &mut exec_id_buf));
                                        builder.push_str(150, "2");
                                        builder.push_str(39, "2");
                                        builder.push_str(55, symbol);
                                        builder.push_str(54, side);
                                        builder.push_u64(38, qty);
                                        builder.push_u64(44, price);
                                        builder.push_u64(32, qty);
                                        builder.push_u64(31, price);
                                        builder.push_u64(151, 0);
                                        builder.push_u64(14, qty);
                                        builder.push_u64(6, price);
                                        let resp = builder.finish_soh_bytes(false, false);
                                        if stream.write_all(&resp).await.is_err() {
                                            closed.store(true, Ordering::Release);
                                            return Ok(());
                                        }
                                    }
                                    CoreOrderVerdict::Rejected => {
                                        let mut builder = FixFrameBuilder::new();
                                        builder.push_str(35, "8");
                                        builder.push_u64(34, out_seq);
                                        out_seq += 1;
                                        builder.push_str(49, "FINGATE");
                                        builder.push_str(56, sender);
                                        builder.push_str(11, cl_ord_id);
                                        builder.push_str(150, "8");
                                        builder.push_str(39, "8");
                                        builder.push_u64(103, 5);
                                        builder.push_str(58, "PreTradeRiskCheckFailed");
                                        let resp = builder.finish_soh_bytes(false, false);
                                        if stream.write_all(&resp).await.is_err() {
                                            closed.store(true, Ordering::Release);
                                            return Ok(());
                                        }
                                    }
                                }
                            }
                            _ => {}
                        }
                    }
                }
            }
        }
        closed.store(true, Ordering::Release);
        Ok(())
    }
}

/// Legacy compatibility wrapper retained for existing Month 4 integration tests.
pub struct SessionShieldTcpServer {
    pub local_addr: SocketAddr,
    listener: TcpListener,
    multiplexer: Arc<Mutex<StrategyPodMultiplexer>>,
    risk: Arc<Mutex<PreTradeRiskEngine>>,
    wal: Arc<Mutex<Option<WriteAheadLog>>>,
    shutdown: Arc<Notify>,
}

impl SessionShieldTcpServer {
    pub async fn bind(
        addr: &str,
        multiplexer: Arc<Mutex<StrategyPodMultiplexer>>,
        risk: Arc<Mutex<PreTradeRiskEngine>>,
        wal: Option<WriteAheadLog>,
    ) -> Result<Self> {
        let listener = TcpListener::bind(addr).await?;
        let local_addr = listener.local_addr()?;
        Ok(Self {
            local_addr,
            listener,
            multiplexer,
            risk,
            wal: Arc::new(Mutex::new(wal)),
            shutdown: Arc::new(Notify::new()),
        })
    }

    pub fn shutdown(&self) {
        self.shutdown.notify_waiters();
    }

    pub async fn run(&self) -> Result<()> {
        let shutdown = self.shutdown.clone();
        loop {
            tokio::select! {
                _ = shutdown.notified() => break,
                accept_res = self.listener.accept() => {
                    let (socket, _) = match accept_res {
                        Ok(conn) => conn,
                        Err(e) => {
                            tracing::warn!("TCP accept error: {:?}", e);
                            continue;
                        }
                    };
                    let _ = socket.set_nodelay(true);
                    let mux = self.multiplexer.clone();
                    let risk = self.risk.clone();
                    let wal = self.wal.clone();
                    let shutdown_child = shutdown.clone();
                    tokio::spawn(async move {
                        let _ = Self::handle_connection(socket, mux, risk, wal, shutdown_child).await;
                    });
                }
            }
        }
        Ok(())
    }

    async fn handle_connection(
        mut stream: TcpStream,
        multiplexer: Arc<Mutex<StrategyPodMultiplexer>>,
        risk: Arc<Mutex<PreTradeRiskEngine>>,
        wal: Arc<Mutex<Option<WriteAheadLog>>>,
        shutdown: Arc<Notify>,
    ) -> Result<()> {
        let mut defragmenter = FixTcpDefragmenter::new();
        let mut read_buf = [0u8; 8192];
        let mut exec_id_buf = [0u8; 24];
        let mut out_seq = 1u64;
        let clock = HardwareTscClock::global();

        loop {
            tokio::select! {
                _ = shutdown.notified() => break,
                read_res = stream.read(&mut read_buf) => {
                    let n = match read_res {
                        Ok(0) | Err(_) => break,
                        Ok(n) => n,
                    };

                    let raw_frames = defragmenter.feed(&read_buf[..n]);
                    for raw_frame in raw_frames {
                        let view = match FixWireView::parse_and_validate(&raw_frame) {
                            Ok(v) => v,
                            Err(_) => continue,
                        };
                        let msg_type = match view.msg_type() {
                            Some(t) => t,
                            None => continue,
                        };

                        match msg_type {
                            "A" => {
                                let sender = view.get_str(49).unwrap_or("STRAT");
                                let mut builder = FixFrameBuilder::new();
                                builder.push_str(35, "A");
                                builder.push_u64(34, out_seq);
                                out_seq += 1;
                                builder.push_str(49, "FINGATE");
                                builder.push_str(56, sender);
                                builder.push_u64(108, 30);
                                let resp = builder.finish_soh_bytes(false, false);
                                if stream.write_all(&resp).await.is_err() {
                                    return Ok(());
                                }
                            }
                            "0" => {
                                let sender = view.get_str(49).unwrap_or("STRAT");
                                let mut builder = FixFrameBuilder::new();
                                builder.push_str(35, "0");
                                builder.push_u64(34, out_seq);
                                out_seq += 1;
                                builder.push_str(49, "FINGATE");
                                builder.push_str(56, sender);
                                let resp = builder.finish_soh_bytes(false, false);
                                if stream.write_all(&resp).await.is_err() {
                                    return Ok(());
                                }
                            }
                            "D" => {
                                let cl_ord_id = view.get_str(11).unwrap_or("ORD-UNKNOWN");
                                let symbol = view.get_str(55).unwrap_or("BTC-USDT");
                                let side = view.get_str(54).unwrap_or("1");
                                let is_buy = side == "1";
                                let qty = view.get_u64(38).unwrap_or(1);
                                let price = view.get_u64(44).unwrap_or(95000);
                                let pod_id = view.get_str(50).unwrap_or("strat-pod-default");
                                let sender = view.get_str(49).unwrap_or("STRAT");
                                let in_seq = view.msg_seq_num().unwrap_or(1);
                                let now_ns = clock.now_nanos();

                                let risk_result = {
                                    let mut r = risk.lock().await;
                                    r.check_order("SHIELD_MAIN_ACC", in_seq, 1, is_buy, price, qty, now_ns)
                                };

                                match risk_result {
                                    Ok(_) => {
                                        let wire_id = {
                                            let mut m = multiplexer.lock().await;
                                            m.register_pod(pod_id);
                                            let w = m.router.register_outbound_order(
                                                pod_id,
                                                cl_ord_id,
                                                symbol,
                                                qty,
                                                price,
                                                is_buy,
                                                now_ns / 1_000_000,
                                            );
                                            m.router.route_inbound_fill(&w, qty);
                                            w
                                        };
                                        {
                                            let mut w_guard = wal.lock().await;
                                            if let Some(ref mut log) = *w_guard {
                                                let _ = log.append(in_seq, now_ns, 0, &raw_frame);
                                            }
                                        }
                                        let mut builder = FixFrameBuilder::new();
                                        builder.push_str(35, "8");
                                        builder.push_u64(34, out_seq);
                                        out_seq += 1;
                                        builder.push_str(49, "FINGATE");
                                        builder.push_str(56, sender);
                                        builder.push_str(37, &wire_id);
                                        builder.push_str(11, cl_ord_id);
                                        builder.push_str(17, format_exec_id(out_seq, &mut exec_id_buf));
                                        builder.push_str(150, "2");
                                        builder.push_str(39, "2");
                                        builder.push_str(55, symbol);
                                        builder.push_str(54, side);
                                        builder.push_u64(38, qty);
                                        builder.push_u64(44, price);
                                        builder.push_u64(32, qty);
                                        builder.push_u64(31, price);
                                        builder.push_u64(151, 0);
                                        builder.push_u64(14, qty);
                                        builder.push_u64(6, price);
                                        let resp = builder.finish_soh_bytes(false, false);
                                        if stream.write_all(&resp).await.is_err() {
                                            return Ok(());
                                        }
                                    }
                                    Err(_) => {
                                        let mut builder = FixFrameBuilder::new();
                                        builder.push_str(35, "8");
                                        builder.push_u64(34, out_seq);
                                        out_seq += 1;
                                        builder.push_str(49, "FINGATE");
                                        builder.push_str(56, sender);
                                        builder.push_str(11, cl_ord_id);
                                        builder.push_str(150, "8");
                                        builder.push_str(39, "8");
                                        builder.push_u64(103, 5);
                                        builder.push_str(58, "PreTradeRiskCheckFailed");
                                        let resp = builder.finish_soh_bytes(false, false);
                                        if stream.write_all(&resp).await.is_err() {
                                            return Ok(());
                                        }
                                    }
                                }
                            }
                            _ => {}
                        }
                    }
                }
            }
        }
        Ok(())
    }
}
