//! Phase D6: `fingate-vopr` — Deterministic Multi-Fault Cluster Simulator (TigerBeetle VOPR-style).
//!
//! Runs a complete simulated 3-node `VSR` gateway cluster + `OrderLifecycleFsm` (`35=G` races) +
//! `PreTradeRiskEngine` + `PortfolioGreeksEngine` (16-pt SIMD SPAN) + simulated exchange matching
//! engine on ONE deterministic thread driven solely by a 64-bit `seed`.
//!
//! Simultaneously injects compound faults:
//! - Primary freezes (`SIGSTOP`) & asymmetric network partitions triggering `VSR` view changes
//! - Stale primary wake-up split-brain attempts (verifying **Invariant `I10`** epoch fencing)
//! - Concurrent `35=G` Cancel/Replace + `PartialFill` + `CancelReject (35=9)` races (**Invariant `I9`**)
//! - Silent disk sector bitrot + automatic peer healing
//! - GCRA bursts & Greeks/SPAN margin breaches (**Invariants `I1`–`I8`**)
//!
//! Any invariant failure prints the exact 64-bit `seed` for 1-second deterministic reproduction.

use crate::oms::order_fsm::{OrderLifecycleFsm, OrderState};
use crate::risk::engine::{AccountRiskConfig, InstrumentRiskConfig, PreTradeRiskEngine};
use crate::risk::portfolio_greeks::{
    ContractGreeks, PortfolioGreekLimits, PortfolioGreeksEngine, SpanRiskArray,
};
use crate::shield::vsr_consensus::{VsrCluster, VsrError};

/// Deterministic 64-bit SplitMix64 PRNG (zero external dependencies, bit-reproducible).
#[derive(Debug, Clone, Copy)]
pub struct SplitMix64 {
    state: u64,
}

impl SplitMix64 {
    #[inline(always)]
    pub const fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    #[inline(always)]
    pub fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    #[inline(always)]
    pub fn gen_range(&mut self, upper: u64) -> u64 {
        if upper == 0 {
            0
        } else {
            self.next_u64() % upper
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VoprViolation {
    pub seed: u64,
    pub tick: u64,
    pub invariant: &'static str,
    pub detail: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct VoprSeedReport {
    pub seed: u64,
    pub ticks_executed: u64,
    pub orders_submitted: u64,
    pub orders_approved: u64,
    pub orders_rejected: u64,
    pub replaces_raced: u64,
    pub fills_applied: u64,
    pub view_changes: u64,
    pub split_brain_blocked: u64,
    pub bitrot_repaired: u64,
    /// Deterministic state digest proving two runs with the same `seed` are 100% bit-identical.
    pub state_digest: u64,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct VoprSuiteSummary {
    pub seeds_tested: u64,
    pub total_ticks: u64,
    pub total_orders_approved: u64,
    pub total_replaces_raced: u64,
    pub total_fills_applied: u64,
    pub total_view_changes: u64,
    pub total_split_brain_blocked: u64,
    pub total_bitrot_repaired: u64,
    pub aggregate_digest: u64,
}

pub struct VoprSimulator;

impl VoprSimulator {
    /// Execute a single deterministic seeded multi-fault cluster run for `ticks` virtual steps.
    pub fn run_seed(seed: u64, ticks: u64) -> Result<VoprSeedReport, VoprViolation> {
        let mut rng = SplitMix64::new(seed);
        let mut cluster = VsrCluster::new();
        let mut fsm = OrderLifecycleFsm::with_capacity(256);

        let mut risk = PreTradeRiskEngine::new();
        let acc_slot = risk.register_account(AccountRiskConfig {
            account_id: "VOPR_ACC_0".to_string(),
            trading_group_id: 1,
            gross_credit_limit: 5_000_000,
            gcra_tau_ns: 2_000_000,         // 500 ops/sec
            gcra_burst_limit_ns: 50_000_000, // 25 burst orders
        });
        risk.register_instrument(
            1,
            InstrumentRiskConfig {
                max_order_qty: 500,
                max_order_notional: 250_000,
                price_collar_bps: 1_000, // 10% collar around ref price
                reference_price: 100,
            },
        );

        let mut greeks = PortfolioGreeksEngine::new(4, 2, 4);
        let glim = PortfolioGreekLimits {
            max_abs_delta_e4: 2_500_000, // 250.0 delta
            max_abs_gamma_e4: 1_000_000,
            max_abs_vega_e4: 1_500_000,
            max_span_loss: 250_000,
        };
        greeks.configure_account(0, 0, glim);
        greeks.configure_house_group(0, glim);
        greeks.set_contract_greeks(
            1,
            ContractGreeks {
                delta_e4: 5_000, // +0.50 delta call
                gamma_e4: 400,
                vega_e4: 800,
                theta_e4: -100,
                span: SpanRiskArray {
                    scenarios: [
                        -80, -60, -40, -20, 0, 20, 40, 60, -90, -70, -50, -30, 10, 30, 50, 70,
                    ],
                },
            },
        );

        let mut active_cl_ids: Vec<(u64, bool, u64)> = Vec::with_capacity(64); // (cl_hash, is_buy, working_qty)
        let mut next_cl_id: u64 = 10_000 + (seed & 0xFFFF);
        let mut virtual_ns: u64 = 1_000_000_000;

        let mut report = VoprSeedReport {
            seed,
            ticks_executed: ticks,
            ..Default::default()
        };

        for tick in 0..ticks {
            // Advance virtual time with realistic jitter (100 us .. 5 ms)
            virtual_ns += 100_000 + rng.gen_range(4_900_000);
            let roll = rng.gen_range(100);

            if roll < 32 {
                // Event A: Submit New Order (35=D) through Risk + Greeks/SPAN + VSR Quorum + OMS FSM
                report.orders_submitted += 1;
                let cl_hash = next_cl_id;
                next_cl_id += 1;
                let is_buy = (rng.next_u64() & 1) == 0;
                let qty = 10 + rng.gen_range(120);
                let price = 95 + rng.gen_range(12); // occasionally hits collar or credit

                let risk_ok = risk
                    .check_order_slot(acc_slot, cl_hash, 1, is_buy, price, qty, virtual_ns)
                    .is_ok();
                if !risk_ok {
                    report.orders_rejected += 1;
                } else {
                    let greeks_ok = greeks
                        .check_and_reserve_working_order(0, 1, is_buy, qty)
                        .is_ok();
                    if !greeks_ok {
                        report.orders_rejected += 1;
                    } else if let Some(primary_id) = cluster.active_primary_id() {
                        let mut payload = [0u8; 24];
                        payload[0..8].copy_from_slice(&cl_hash.to_le_bytes());
                        payload[8..16].copy_from_slice(&qty.to_le_bytes());
                        payload[16..24].copy_from_slice(&price.to_le_bytes());
                        match cluster.submit_order_on_node(primary_id, &payload) {
                            Ok(_) => {
                                if fsm
                                    .submit_new(cl_hash, 0, 1, is_buy, qty, price as i64)
                                    .is_ok()
                                {
                                    report.orders_approved += 1;
                                    active_cl_ids.push((cl_hash, is_buy, qty));
                                } else {
                                    greeks.on_working_order_cancel(0, 1, is_buy, qty);
                                    report.orders_rejected += 1;
                                }
                            }
                            Err(_) => {
                                // Quorum unavailable: rollback working reservation cleanly
                                greeks.on_working_order_cancel(0, 1, is_buy, qty);
                                report.orders_rejected += 1;
                            }
                        }
                    } else {
                        greeks.on_working_order_cancel(0, 1, is_buy, qty);
                        report.orders_rejected += 1;
                    }
                }
            } else if roll < 54 && !active_cl_ids.is_empty() {
                // Event B: Concurrent 35=G Cancel/Replace Race (size-up OR size-down!)
                let pick = (rng.next_u64() as usize) % active_cl_ids.len();
                let (orig_id, is_buy, _orig_qty) = active_cl_ids[pick];
                if let Some(slot) = fsm.get(orig_id) {
                    if slot.state == OrderState::New || slot.state == OrderState::PartiallyFilled {
                        let new_id = next_cl_id;
                        next_cl_id += 1;
                        let delta_dir = (rng.next_u64() & 1) == 0;
                        let candidate_qty = if delta_dir {
                            slot.working_qty + 10 + rng.gen_range(40)
                        } else {
                            let min_q = slot.cum_qty + 1;
                            if slot.working_qty > min_q {
                                min_q + rng.gen_range(slot.working_qty - min_q)
                            } else {
                                slot.working_qty + 5
                            }
                        };
                        let extra_reserve = candidate_qty.saturating_sub(slot.working_qty);
                        let reserve_ok = if extra_reserve > 0 {
                            greeks
                                .check_and_reserve_working_order(0, 1, is_buy, extra_reserve)
                                .is_ok()
                        } else {
                            true
                        };
                        if reserve_ok {
                            if fsm
                                .request_replace(orig_id, new_id, candidate_qty, 101)
                                .is_ok()
                            {
                                report.replaces_raced += 1;
                                // Immediately inject an adversarial concurrent PartialFill on 50% of replaces!
                                if (rng.next_u64() & 1) == 0 {
                                    if let Some(s_now) = fsm.get(orig_id) {
                                        let max_rem = s_now.working_qty.saturating_sub(s_now.cum_qty);
                                        if max_rem > 0 {
                                            let fill_qty = 1 + rng.gen_range(max_rem);
                                            if let Ok(ftr) = fsm.on_fill(orig_id, fill_qty) {
                                                report.fills_applied += 1;
                                                greeks.on_working_order_fill(0, 1, is_buy, fill_qty);
                                                let extra_rel = (-ftr.exposure_delta)
                                                    .saturating_sub(fill_qty as i64)
                                                    .max(0) as u64;
                                                if extra_rel > 0 {
                                                    greeks.on_working_order_cancel(0, 1, is_buy, extra_rel);
                                                }
                                            }
                                        }
                                    }
                                }
                                // Resolve via ReplaceAck or CancelReject (35=9)
                                let res = if (rng.next_u64() & 1) == 0 {
                                    let r = fsm.on_replace_ack(new_id);
                                    if r.is_ok() {
                                        active_cl_ids[pick].0 = new_id;
                                    }
                                    r
                                } else {
                                    fsm.on_cancel_reject(orig_id)
                                };
                                if let Ok(tr) = res {
                                    if tr.exposure_delta < 0 {
                                        greeks.on_working_order_cancel(
                                            0,
                                            1,
                                            is_buy,
                                            (-tr.exposure_delta) as u64,
                                        );
                                    }
                                    if tr.state == OrderState::Filled {
                                        active_cl_ids.swap_remove(pick);
                                    }
                                }
                            } else if extra_reserve > 0 {
                                greeks.on_working_order_cancel(0, 1, is_buy, extra_reserve);
                            }
                        }
                    }
                }
            } else if roll < 72 && !active_cl_ids.is_empty() {
                // Event C: PartialFill / Full Fill or Cancel lifecycle
                let pick = (rng.next_u64() as usize) % active_cl_ids.len();
                let (cl_id, is_buy, _) = active_cl_ids[pick];
                if let Some(slot) = fsm.get(cl_id) {
                    if slot.leaves_qty > 0 {
                        if (rng.next_u64() % 3) == 0 {
                            if fsm.request_cancel(cl_id).is_ok() {
                                if let Ok(ctr) = fsm.on_cancel_ack(cl_id) {
                                    if ctr.exposure_delta < 0 {
                                        greeks.on_working_order_cancel(
                                            0,
                                            1,
                                            is_buy,
                                            (-ctr.exposure_delta) as u64,
                                        );
                                    }
                                    active_cl_ids.swap_remove(pick);
                                }
                            }
                        } else {
                            let fill_qty = 1 + rng.gen_range(slot.leaves_qty);
                            if let Ok(tr) = fsm.on_fill(cl_id, fill_qty) {
                                report.fills_applied += 1;
                                greeks.on_working_order_fill(0, 1, is_buy, fill_qty);
                                if tr.state == OrderState::Filled {
                                    active_cl_ids.swap_remove(pick);
                                }
                            }
                        }
                    } else {
                        active_cl_ids.swap_remove(pick);
                    }
                }
            } else if roll < 86 {
                // Event D: Network Partition / Primary Freeze + Quorum View Change + Stale Split-Brain Attack!
                if let Some(old_primary) = cluster.active_primary_id() {
                    let backup_init = (old_primary + 1) % 3;
                    // Freeze & partition the current Primary (simulate SIGSTOP / ToR switch drop)
                    cluster.set_frozen(old_primary, true);
                    cluster.set_partitioned(old_primary, true);

                    if cluster.trigger_view_change(backup_init).is_ok() {
                        report.view_changes += 1;
                    }

                    // Unfreeze old Primary while it still holds stale view and attempt split-brain write!
                    cluster.set_frozen(old_primary, false);
                    let stale_res = cluster.submit_order_on_node(old_primary, b"STALE-SPLIT-BRAIN");
                    match stale_res {
                        Ok(_) => {
                            return Err(VoprViolation {
                                seed,
                                tick,
                                invariant: "I10_SPLIT_BRAIN_FENCING",
                                detail: format!(
                                    "stale primary {} emitted order after view change!",
                                    old_primary
                                ),
                            });
                        }
                        Err(VsrError::StaleFencingView { .. }) => {
                            report.split_brain_blocked += 1;
                        }
                        Err(_) => {}
                    }

                    // Heal partition and catch up old primary cleanly as Backup
                    cluster.set_partitioned(old_primary, false);
                    let _ = cluster.catchup_replica(old_primary);
                }
            } else {
                // Event E: Silent Disk Sector Bitrot Injection + Protocol-Aware Peer Repair!
                let victim = (rng.next_u64() % 3) as u8;
                let log_len = cluster.replicas[victim as usize].log.len() as u64;
                if log_len > 0 {
                    let bad_op = 1 + rng.gen_range(log_len);
                    if cluster.inject_disk_bitrot(victim, bad_op) {
                        match cluster.repair_bitrot_from_peers(victim) {
                            Ok(repaired) => {
                                report.bitrot_repaired += repaired as u64;
                            }
                            Err(e) => {
                                return Err(VoprViolation {
                                    seed,
                                    tick,
                                    invariant: "I10_BITROT_PEER_REPAIR",
                                    detail: format!(
                                        "replica {} failed to heal op {}: {:?}",
                                        victim, bad_op, e
                                    ),
                                });
                            }
                        }
                    }
                }
            }

            // Continuous Formal Invariant Checks on EVERY virtual tick!
            if let Err(msg) = fsm.verify_invariants() {
                return Err(VoprViolation {
                    seed,
                    tick,
                    invariant: "I9_OMS_CONSERVATIVE_EXPOSURE",
                    detail: msg.to_string(),
                });
            }
            if let Err(msg) = cluster.verify_cluster_invariants() {
                return Err(VoprViolation {
                    seed,
                    tick,
                    invariant: "I10_VSR_QUORUM_FENCING",
                    detail: msg.to_string(),
                });
            }
            if let Some(acc_g) = greeks.account_state(0) {
                if acc_g.net_delta_e4.abs() > acc_g.limits.max_abs_delta_e4
                    || acc_g.net_gamma_e4.abs() > acc_g.limits.max_abs_gamma_e4
                    || acc_g.net_vega_e4.abs() > acc_g.limits.max_abs_vega_e4
                {
                    return Err(VoprViolation {
                        seed,
                        tick,
                        invariant: "I4_PORTFOLIO_GREEKS_BOUND",
                        detail: "committed portfolio Greeks breached hard account ceiling".to_string(),
                    });
                }
                let worst = acc_g
                    .portfolio_span
                    .scenarios
                    .iter()
                    .copied()
                    .min()
                    .unwrap_or(0);
                if worst < -acc_g.limits.max_span_loss {
                    return Err(VoprViolation {
                        seed,
                        tick,
                        invariant: "I4_SIMD_SPAN_MARGIN_BOUND",
                        detail: format!(
                            "committed portfolio SPAN loss {} exceeded -{}",
                            worst, acc_g.limits.max_span_loss
                        ),
                    });
                }
            }
        }

        // Compute deterministic final digest across cluster, FSM, and Greeks state
        let mut digest = seed ^ 0x517c_c1b7_2722_0a95;
        digest = digest
            .wrapping_mul(0x1000_0000_01b3)
            .wrapping_add(cluster.venue_fencing_view)
            .wrapping_add(cluster.committed_orders.len() as u64)
            .wrapping_add(fsm.total_reserved_exposure_qty());
        if let Some(acc_g) = greeks.account_state(0) {
            digest = digest
                .wrapping_mul(0x1000_0000_01b3)
                .wrapping_add(acc_g.net_delta_e4 as u64);
        }
        report.state_digest = digest;

        Ok(report)
    }

    /// Run a batch of deterministic seeds (`start_seed..start_seed + num_seeds`) and aggregate stats.
    pub fn run_seed_suite(
        start_seed: u64,
        num_seeds: u64,
        ticks_per_seed: u64,
    ) -> Result<VoprSuiteSummary, VoprViolation> {
        let mut summary = VoprSuiteSummary::default();
        for s in start_seed..start_seed + num_seeds {
            let r = Self::run_seed(s, ticks_per_seed)?;
            summary.seeds_tested += 1;
            summary.total_ticks += r.ticks_executed;
            summary.total_orders_approved += r.orders_approved;
            summary.total_replaces_raced += r.replaces_raced;
            summary.total_fills_applied += r.fills_applied;
            summary.total_view_changes += r.view_changes;
            summary.total_split_brain_blocked += r.split_brain_blocked;
            summary.total_bitrot_repaired += r.bitrot_repaired;
            summary.aggregate_digest ^= r.state_digest.rotate_left((s & 63) as u32);
        }
        Ok(summary)
    }
}
