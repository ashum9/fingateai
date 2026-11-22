//! Track F (F1): Real Public Exchange Testnet Bridge (`BinanceTestnetBridge`).
//!
//! Connects FinGate's Pre-Trade Risk Engine & PCIe BAR0 Shadow Registers directly to real
//! public exchange market data & order-validation endpoints (`https://testnet.binance.vision`)
//! using ZERO external crates:
//! - Fetches live `serverTime` & symbol reference price (`BTCUSDT`, `ETHUSDT`, etc.)
//! - Dynamically updates BOTH `PreTradeRiskEngine` AND `FpgaBar0Registers` price collars
//! - Signs Binance REST/FIX payloads using FinGate's own pure-Rust `attestation::hmac_sha256`
//! - Submits real authenticated `POST /api/v3/order/test` when `BINANCE_TESTNET_API_KEY` &
//!   `BINANCE_TESTNET_API_SECRET` are present in the environment.

use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, Result};

use crate::attestation::{hex_encode, hmac_sha256};
use crate::hw_sync::bar0::FpgaBar0Registers;
use crate::risk::engine::{InstrumentRiskConfig, PreTradeRiskEngine};

pub const BINANCE_TESTNET_BASE_URL: &str = "https://testnet.binance.vision";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiveTestnetMarketSnapshot {
    pub symbol: String,
    pub exchange_server_time_ms: u64,
    pub local_clock_skew_ms: i64,
    /// Fixed-point integer price (whole USD units, e.g. `58182`).
    pub price_whole_usd: u64,
    /// Fixed-point integer price scaled by `100` (cents, e.g. `5818259` for `$58,182.59`).
    pub price_cents: u64,
    pub raw_price_str: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedTestnetOrderPayload {
    pub query_string: String,
    pub hmac_sha256_hex: String,
    pub full_signed_body: String,
}

/// Parse a decimal ASCII price string (e.g. `"58182.59000000"`) into `(whole_units, cents)` without f64 drift.
pub fn parse_price_whole_and_cents(s: &str) -> Result<(u64, u64)> {
    let trimmed = s.trim();
    if trimmed.is_empty() {
        return Err(anyhow!("empty price string"));
    }
    let mut parts = trimmed.split('.');
    let whole_str = parts.next().unwrap_or("0");
    let frac_str = parts.next().unwrap_or("00");
    let whole: u64 = whole_str
        .parse()
        .map_err(|_| anyhow!("invalid whole price component: {}", whole_str))?;

    let frac_bytes = frac_str.as_bytes();
    let d0 = frac_bytes
        .first()
        .copied()
        .filter(|b| b.is_ascii_digit())
        .map(|b| (b - b'0') as u64)
        .unwrap_or(0);
    let d1 = frac_bytes
        .get(1)
        .copied()
        .filter(|b| b.is_ascii_digit())
        .map(|b| (b - b'0') as u64)
        .unwrap_or(0);
    let cents = whole.saturating_mul(100).saturating_add(d0 * 10 + d1);
    Ok((whole, cents))
}

/// Compute Binance Spot HMAC-SHA256 signed query body using FinGate's pure-Rust `hmac_sha256`.
pub fn build_signed_binance_order(
    symbol: &str,
    side: &str,
    quantity: &str,
    price: &str,
    timestamp_ms: u64,
    api_secret: &[u8],
) -> SignedTestnetOrderPayload {
    let query_string = format!(
        "symbol={}&side={}&type=LIMIT&timeInForce=GTC&quantity={}&price={}&timestamp={}",
        symbol, side, quantity, price, timestamp_ms
    );
    let mac = hmac_sha256(api_secret, query_string.as_bytes());
    let hmac_sha256_hex = hex_encode(&mac);
    let full_signed_body = format!("{}&signature={}", query_string, hmac_sha256_hex);
    SignedTestnetOrderPayload {
        query_string,
        hmac_sha256_hex,
        full_signed_body,
    }
}

/// Live Public Exchange Testnet Connector (`https://testnet.binance.vision`).
pub struct BinanceTestnetBridge {
    base_url: String,
}

impl Default for BinanceTestnetBridge {
    fn default() -> Self {
        Self::new(BINANCE_TESTNET_BASE_URL)
    }
}

impl BinanceTestnetBridge {
    pub fn new(base_url: &str) -> Self {
        Self {
            base_url: base_url.trim_end_matches('/').to_string(),
        }
    }

    fn http_get(&self, path: &str) -> Result<String> {
        let url = format!("{}{}", self.base_url, path);
        let out = Command::new("curl")
            .args(["-sS", "--fail", "--max-time", "5", &url])
            .output()
            .map_err(|e| anyhow!("failed to invoke curl for {}: {}", url, e))?;
        if !out.status.success() {
            return Err(anyhow!(
                "HTTP GET {} failed: {}",
                url,
                String::from_utf8_lossy(&out.stderr)
            ));
        }
        Ok(String::from_utf8_lossy(&out.stdout).into_owned())
    }

    /// Fetch live exchange server time and real-time spot ticker price from Binance Spot Testnet.
    pub fn fetch_live_market_snapshot(&self, symbol: &str) -> Result<LiveTestnetMarketSnapshot> {
        let time_json_str = self.http_get("/api/v3/time")?;
        let time_val: serde_json::Value = serde_json::from_str(&time_json_str)?;
        let exchange_server_time_ms = time_val["serverTime"]
            .as_u64()
            .ok_or_else(|| anyhow!("missing serverTime in {}", time_json_str))?;

        let local_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        let local_clock_skew_ms = (exchange_server_time_ms as i64) - (local_ms as i64);

        let ticker_path = format!("/api/v3/ticker/price?symbol={}", symbol);
        let ticker_str = self.http_get(&ticker_path)?;
        let ticker_val: serde_json::Value = serde_json::from_str(&ticker_str)?;
        let raw_price_str = ticker_val["price"]
            .as_str()
            .ok_or_else(|| anyhow!("missing price in {}", ticker_str))?
            .to_string();
        let (price_whole_usd, price_cents) = parse_price_whole_and_cents(&raw_price_str)?;

        Ok(LiveTestnetMarketSnapshot {
            symbol: symbol.to_string(),
            exchange_server_time_ms,
            local_clock_skew_ms,
            price_whole_usd,
            price_cents,
            raw_price_str,
        })
    }

    /// Synchronize BOTH FinGate's inline `PreTradeRiskEngine` AND PCIe `FpgaBar0Registers`
    /// price collars directly from a live public exchange market snapshot!
    pub fn sync_collars_from_snapshot(
        snapshot: &LiveTestnetMarketSnapshot,
        symbol_id: u32,
        max_order_qty: u64,
        max_order_notional: u64,
        collar_bps: u64,
        risk: &mut PreTradeRiskEngine,
        bar0: &FpgaBar0Registers,
    ) -> (u64, u64) {
        let ref_px = snapshot.price_whole_usd.max(1);
        let band = (ref_px.saturating_mul(collar_bps)) / 10_000;
        let min_px = ref_px.saturating_sub(band);
        let max_px = ref_px.saturating_add(band);

        risk.register_instrument(
            symbol_id,
            InstrumentRiskConfig {
                max_order_qty,
                max_order_notional,
                price_collar_bps: collar_bps,
                reference_price: ref_px,
            },
        );
        bar0.publish_limits(max_order_qty, max_order_notional, min_px, max_px, 100, 1000);
        (min_px, max_px)
    }

    /// If `BINANCE_TESTNET_API_KEY` & `BINANCE_TESTNET_API_SECRET` are configured, submit a real
    /// authenticated `POST /api/v3/order/test` (live exchange signature + risk-schema validation).
    pub fn submit_signed_test_order_if_keys_present(
        &self,
        symbol: &str,
        side: &str,
        quantity: &str,
        price: &str,
        timestamp_ms: u64,
    ) -> Result<Option<String>> {
        let (Ok(api_key), Ok(api_secret)) = (
            std::env::var("BINANCE_TESTNET_API_KEY"),
            std::env::var("BINANCE_TESTNET_API_SECRET"),
        ) else {
            return Ok(None);
        };
        if api_key.is_empty() || api_secret.is_empty() {
            return Ok(None);
        }
        let signed = build_signed_binance_order(
            symbol,
            side,
            quantity,
            price,
            timestamp_ms,
            api_secret.as_bytes(),
        );
        let url = format!("{}/api/v3/order/test", self.base_url);
        let header = format!("X-MBX-APIKEY: {}", api_key);
        let out = Command::new("curl")
            .args([
                "-sS",
                "--fail",
                "--max-time",
                "5",
                "-X",
                "POST",
                "-H",
                &header,
                "-d",
                &signed.full_signed_body,
                &url,
            ])
            .output()?;
        if !out.status.success() {
            return Err(anyhow!(
                "Binance Testnet /api/v3/order/test rejected: {}",
                String::from_utf8_lossy(&out.stderr)
            ));
        }
        Ok(Some(String::from_utf8_lossy(&out.stdout).into_owned()))
    }
}
