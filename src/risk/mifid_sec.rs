//! Month 3, Week 2: MiFID II RTS 6 & SEC Rule 15c3-5 Compliance Engine.
//!
//! Implements statutory institutional market access controls:
//! 1. **SEC Rule 15c3-5 ("Market Access Rule"):**
//!    - Mandatory credit threshold controls preventing capital over-commitment.
//!    - Erroneous order entry barriers (price collars & fat-finger limits).
//!    - Immediate halt and regulatory audit logging upon threshold breach.
//! 2. **MiFID II RTS 6 (Commission Delegated Regulation EU 2017/589):**
//!    - Real-time Order-to-Trade Ratio (OTR) calculation for count and volume.
//!    - Automated throttling when OTR exceeds venue regulatory threshold (e.g. 50:1).
//!    - Runaway algorithm kill switch: Automatic emergency halt if message rate spikes.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Sec15c3Config {
    pub max_daily_notional_limit: u64,
    pub single_order_max_notional: u64,
    pub hard_credit_ceiling: u64,
}

impl Default for Sec15c3Config {
    fn default() -> Self {
        Self {
            max_daily_notional_limit: 10_000_000_000, // $10M
            single_order_max_notional: 1_000_000_000, // $1M
            hard_credit_ceiling: 25_000_000_000,      // $25M
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MifidRts6Config {
    pub max_otr_count_ratio: f64,   // e.g. 50.0 orders per trade
    pub max_otr_volume_ratio: f64,  // e.g. 100.0 volume per trade
    pub runaway_message_threshold: usize, // e.g. 100 orders in 100ms
    pub runaway_window_ms: u64,
}

impl Default for MifidRts6Config {
    fn default() -> Self {
        Self {
            max_otr_count_ratio: 50.0,
            max_otr_volume_ratio: 100.0,
            runaway_message_threshold: 50,
            runaway_window_ms: 100,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum ComplianceViolation {
    SecDailyNotionalLimitExceeded { limit: u64, requested: u64 },
    SecSingleOrderNotionalExceeded { limit: u64, requested: u64 },
    SecCreditCeilingBreached { ceiling: u64, current: u64 },
    MifidOtrCountBreached { current_otr: f64, max_allowed: f64 },
    MifidOtrVolumeBreached { current_otr: f64, max_allowed: f64 },
    MifidRunawayAlgorithmHalt { count: usize, window_ms: u64 },
}

pub struct RegulatoryComplianceMonitor {
    pub sec_cfg: Sec15c3Config,
    pub mifid_cfg: MifidRts6Config,
    pub daily_accumulated_notional: u64,
    pub current_credit_utilized: u64,
    pub total_orders_entered: u64,
    pub total_trades_executed: u64,
    pub total_volume_entered: u64,
    pub total_volume_executed: u64,
    pub recent_order_timestamps_ms: Vec<u64>,
    pub is_halted: bool,
    pub violations_log: Vec<(u64, ComplianceViolation)>,
}

impl RegulatoryComplianceMonitor {
    pub fn new(sec_cfg: Sec15c3Config, mifid_cfg: MifidRts6Config) -> Self {
        Self {
            sec_cfg,
            mifid_cfg,
            daily_accumulated_notional: 0,
            current_credit_utilized: 0,
            total_orders_entered: 0,
            total_trades_executed: 0,
            total_volume_entered: 0,
            total_volume_executed: 0,
            recent_order_timestamps_ms: Vec::with_capacity(1024),
            is_halted: false,
            violations_log: Vec::new(),
        }
    }

    /// Evaluate SEC 15c3-5 and MiFID II RTS 6 constraints before order release.
    pub fn evaluate_order(
        &mut self,
        order_notional: u64,
        order_qty: u64,
        now_ms: u64,
    ) -> Result<(), ComplianceViolation> {
        if self.is_halted {
            return Err(ComplianceViolation::MifidRunawayAlgorithmHalt {
                count: self.mifid_cfg.runaway_message_threshold,
                window_ms: self.mifid_cfg.runaway_window_ms,
            });
        }

        // 1. SEC 15c3-5 Single Order Limit
        if order_notional > self.sec_cfg.single_order_max_notional {
            let v = ComplianceViolation::SecSingleOrderNotionalExceeded {
                limit: self.sec_cfg.single_order_max_notional,
                requested: order_notional,
            };
            self.violations_log.push((now_ms, v.clone()));
            return Err(v);
        }

        // 2. SEC 15c3-5 Daily Cumulative Limit
        if self.daily_accumulated_notional.saturating_add(order_notional) > self.sec_cfg.max_daily_notional_limit {
            let v = ComplianceViolation::SecDailyNotionalLimitExceeded {
                limit: self.sec_cfg.max_daily_notional_limit,
                requested: self.daily_accumulated_notional.saturating_add(order_notional),
            };
            self.violations_log.push((now_ms, v.clone()));
            return Err(v);
        }

        // 3. SEC 15c3-5 Hard Credit Ceiling
        if self.current_credit_utilized.saturating_add(order_notional) > self.sec_cfg.hard_credit_ceiling {
            let v = ComplianceViolation::SecCreditCeilingBreached {
                ceiling: self.sec_cfg.hard_credit_ceiling,
                current: self.current_credit_utilized.saturating_add(order_notional),
            };
            self.violations_log.push((now_ms, v.clone()));
            return Err(v);
        }

        // 4. MiFID II Runaway Algorithm Check (Message Storm Detection)
        self.recent_order_timestamps_ms.retain(|&t| now_ms.saturating_sub(t) <= self.mifid_cfg.runaway_window_ms);
        if self.recent_order_timestamps_ms.len() >= self.mifid_cfg.runaway_message_threshold {
            self.is_halted = true;
            let v = ComplianceViolation::MifidRunawayAlgorithmHalt {
                count: self.recent_order_timestamps_ms.len(),
                window_ms: self.mifid_cfg.runaway_window_ms,
            };
            self.violations_log.push((now_ms, v.clone()));
            return Err(v);
        }

        // 5. MiFID II Order-to-Trade Ratio (OTR) Checks (after a warm-up period of 20 orders)
        if self.total_orders_entered > 20 {
            let count_otr = (self.total_orders_entered + 1) as f64 / self.total_trades_executed.max(1) as f64;
            if count_otr > self.mifid_cfg.max_otr_count_ratio {
                let v = ComplianceViolation::MifidOtrCountBreached {
                    current_otr: (count_otr * 100.0).round() / 100.0,
                    max_allowed: self.mifid_cfg.max_otr_count_ratio,
                };
                self.violations_log.push((now_ms, v.clone()));
                return Err(v);
            }

            let vol_otr = (self.total_volume_entered + order_qty) as f64 / self.total_volume_executed.max(1) as f64;
            if vol_otr > self.mifid_cfg.max_otr_volume_ratio {
                let v = ComplianceViolation::MifidOtrVolumeBreached {
                    current_otr: (vol_otr * 100.0).round() / 100.0,
                    max_allowed: self.mifid_cfg.max_otr_volume_ratio,
                };
                self.violations_log.push((now_ms, v.clone()));
                return Err(v);
            }
        }

        // Passed all checks! Update accumulators
        self.daily_accumulated_notional += order_notional;
        self.current_credit_utilized += order_notional;
        self.total_orders_entered += 1;
        self.total_volume_entered += order_qty;
        self.recent_order_timestamps_ms.push(now_ms);

        Ok(())
    }

    /// Record a fill execution report to balance credit and update OTR denominator.
    pub fn record_fill(&mut self, filled_notional: u64, filled_qty: u64) {
        self.current_credit_utilized = self.current_credit_utilized.saturating_sub(filled_notional);
        self.total_trades_executed += 1;
        self.total_volume_executed += filled_qty;
    }

    pub fn compute_count_otr(&self) -> f64 {
        self.total_orders_entered as f64 / self.total_trades_executed.max(1) as f64
    }

    pub fn compute_volume_otr(&self) -> f64 {
        self.total_volume_entered as f64 / self.total_volume_executed.max(1) as f64
    }
}
