//! Month 5, Week 3: High-Performance Lock-Free Gateway Telemetry & Prometheus Exporter.
//!
//! Exposes institutional metrics for Grafana / Datadog dashboards:
//! - Order ingress / egress rates and rejection counts.
//! - Emergency kill-switch status gauge.
//! - Active working order inventory.
//! - Zero hot-path lock contention using relaxed atomics.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Instant;

pub struct GatewayTelemetry {
    pub start_time: Instant,
    pub orders_ingress_total: AtomicU64,
    pub orders_egress_total: AtomicU64,
    pub orders_rejected_total: AtomicU64,
    pub fills_routed_total: AtomicU64,
    pub cancels_routed_total: AtomicU64,
    pub active_working_orders: AtomicU64,
    pub kill_switch_active: AtomicBool,
}

impl GatewayTelemetry {
    pub fn new() -> Self {
        Self {
            start_time: Instant::now(),
            orders_ingress_total: AtomicU64::new(0),
            orders_egress_total: AtomicU64::new(0),
            orders_rejected_total: AtomicU64::new(0),
            fills_routed_total: AtomicU64::new(0),
            cancels_routed_total: AtomicU64::new(0),
            active_working_orders: AtomicU64::new(0),
            kill_switch_active: AtomicBool::new(false),
        }
    }

    #[inline(always)]
    pub fn record_order_ingress(&self) {
        self.orders_ingress_total.fetch_add(1, Ordering::Relaxed);
    }

    #[inline(always)]
    pub fn record_order_egress(&self) {
        self.orders_egress_total.fetch_add(1, Ordering::Relaxed);
        self.active_working_orders.fetch_add(1, Ordering::Relaxed);
    }

    #[inline(always)]
    pub fn record_order_rejected(&self) {
        self.orders_rejected_total.fetch_add(1, Ordering::Relaxed);
    }

    #[inline(always)]
    pub fn record_fill(&self, is_done: bool) {
        self.fills_routed_total.fetch_add(1, Ordering::Relaxed);
        if is_done {
            let _ = self.active_working_orders.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |c| Some(c.saturating_sub(1)));
        }
    }

    #[inline(always)]
    pub fn record_cancel(&self) {
        self.cancels_routed_total.fetch_add(1, Ordering::Relaxed);
        let _ = self.active_working_orders.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |c| Some(c.saturating_sub(1)));
    }

    #[inline(always)]
    pub fn set_kill_switch(&self, active: bool) {
        self.kill_switch_active.store(active, Ordering::Relaxed);
    }

    /// Render Prometheus scrape format text response.
    pub fn render_prometheus(&self) -> String {
        let uptime = self.start_time.elapsed().as_secs();
        let ingress = self.orders_ingress_total.load(Ordering::Relaxed);
        let egress = self.orders_egress_total.load(Ordering::Relaxed);
        let rejected = self.orders_rejected_total.load(Ordering::Relaxed);
        let fills = self.fills_routed_total.load(Ordering::Relaxed);
        let cancels = self.cancels_routed_total.load(Ordering::Relaxed);
        let working = self.active_working_orders.load(Ordering::Relaxed);
        let ks = if self.kill_switch_active.load(Ordering::Relaxed) { 1 } else { 0 };

        format!(
            "# HELP fingate_orders_ingress_total Total orders received from internal strategy pods\n\
             # TYPE fingate_orders_ingress_total counter\n\
             fingate_orders_ingress_total {}\n\n\
             # HELP fingate_orders_egress_total Total orders routed to external exchanges\n\
             # TYPE fingate_orders_egress_total counter\n\
             fingate_orders_egress_total {}\n\n\
             # HELP fingate_orders_rejected_total Total orders rejected by pre-trade risk or kill-switch\n\
             # TYPE fingate_orders_rejected_total counter\n\
             fingate_orders_rejected_total {}\n\n\
             # HELP fingate_fills_routed_total Total execution report fills routed back to pods\n\
             # TYPE fingate_fills_routed_total counter\n\
             fingate_fills_routed_total {}\n\n\
             # HELP fingate_cancels_routed_total Total order cancellations executed\n\
             # TYPE fingate_cancels_routed_total counter\n\
             fingate_cancels_routed_total {}\n\n\
             # HELP fingate_active_working_orders Current active working order inventory\n\
             # TYPE fingate_active_working_orders gauge\n\
             fingate_active_working_orders {}\n\n\
             # HELP fingate_kill_switch_active Emergency kill switch status (1 = active, 0 = normal)\n\
             # TYPE fingate_kill_switch_active gauge\n\
             fingate_kill_switch_active {}\n\n\
             # HELP fingate_uptime_seconds Process uptime in seconds\n\
             # TYPE fingate_uptime_seconds counter\n\
             fingate_uptime_seconds {}\n",
            ingress, egress, rejected, fills, cancels, working, ks, uptime
        )
    }
}
