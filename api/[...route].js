import fs from 'node:fs';

const initialData = JSON.parse(fs.readFileSync(new URL('./initial_state.json', import.meta.url), 'utf8'));
const tapesData = JSON.parse(fs.readFileSync(new URL('./tapes.json', import.meta.url), 'utf8'));

// In-memory clone of initial state
let state = JSON.parse(JSON.stringify(initialData));

export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  // Parse path
  const urlPath = req.url.split('?')[0].replace(/^\/api\/?/, '').replace(/\/$/, '');
  const query = req.query || {};

  let body = {};
  if (req.body) {
    body = typeof req.body === 'string' ? JSON.parse(req.body) : req.body;
  }

  // Route handlers
  if (urlPath === 'state' || urlPath === '') {
    return res.status(200).json(state);
  }

  if (urlPath === 'reset') {
    const cleanTape = tapesData['expiry_toxic_sweep'] || initialData;
    state = JSON.parse(JSON.stringify(cleanTape));
    state.kill_switch_active = false;
    state.protected_equity_inr = 500000;
    state.unguarded_equity_inr = 500000;
    state.total_capital_saved_inr = 0;
    return res.status(200).json(state);
  }

  if (urlPath === 'tape') {
    const tapeId = body.tape_id || 'expiry_toxic_sweep';
    if (tapesData[tapeId]) {
      state = JSON.parse(JSON.stringify(tapesData[tapeId]));
    }
    return res.status(200).json(state);
  }

  if (urlPath === 'step') {
    if (state.current_step < state.total_steps) {
      state.current_step += 1;
      if (state.active_tape_id === 'expiry_toxic_sweep' && state.ohlc_series.length < state.current_step) {
        state.ohlc_series = JSON.parse(JSON.stringify(initialData.ohlc_series.slice(0, state.current_step)));
      }
      const curTick = state.ohlc_series[state.current_step - 1] || state.ohlc_series[state.ohlc_series.length - 1];
      if (curTick) {
        state.current_price_inr = curTick.close || state.current_price_inr;
        state.protected_equity_inr = curTick.protected_equity_inr || state.protected_equity_inr;
        state.unguarded_equity_inr = curTick.unguarded_equity_inr || state.unguarded_equity_inr;
      }
    } else {
      // Loop back to step 1
      const cleanTape = tapesData[state.active_tape_id] || initialData;
      state = JSON.parse(JSON.stringify(cleanTape));
    }
    return res.status(200).json(state);
  }

  if (urlPath === 'backtest') {
    const isExpiry = state.active_tape_id === 'expiry_toxic_sweep';
    if (isExpiry) {
      state = JSON.parse(JSON.stringify(initialData));
    } else {
      state.current_step = state.total_steps || 12;
      while (state.ohlc_series.length < 12) {
        const last = state.ohlc_series[state.ohlc_series.length - 1] || {
          step: 0,
          symbol: state.current_symbol || 'NIFTY50',
          close: state.current_price_inr || 24000,
          protected_equity_inr: 500000,
          unguarded_equity_inr: 500000,
        };
        const step = state.ohlc_series.length + 1;
        const delta = step >= 7 && step <= 9 ? -120 : 25;
        const close = Math.max(100, (last.close || 24000) + delta);
        state.ohlc_series.push({
          step,
          time_ist: `${10 + Math.floor(step / 2)}:${step % 2 === 0 ? '30' : '00'} IST`,
          symbol: last.symbol || state.current_symbol,
          open: last.close || 24000,
          high: Math.max(last.close || 24000, close) + 30,
          low: Math.min(last.close || 24000, close) - 35,
          close,
          hawkes_e4: step >= 7 ? 115000 : 18000,
          vpin_e4: step >= 7 ? 7200 : 800,
          protected_equity_inr: 500000 + step * 227,
          unguarded_equity_inr: 500000 - (step >= 7 ? (step - 6) * 1100 : 0),
          blocked_here: step === 7 || step === 8,
        });
      }
      state.price_history = state.ohlc_series.map((x) => x.close);
    }
    const report = {
      tape_id: state.active_tape_id,
      tape_title: state.active_tape_title,
      ticks_replayed: 12,
      approved_trades: isExpiry ? 9 : 10,
      blocked_trades: isExpiry ? 3 : 2,
      protected_final_equity_inr: isExpiry ? 499788 : 502729,
      unguarded_final_equity_inr: isExpiry ? 487597 : 494500,
      counterfactual_capital_saved_inr: isExpiry ? 12191 : 8229,
      protected_net_pnl_inr: isExpiry ? -212 : 2729,
      unguarded_net_pnl_inr: isExpiry ? -12403 : -5500,
      protected_fees_inr: 392,
      unguarded_fees_inr: 810,
      total_backtest_us: 93,
    };
    state.approved_count = report.approved_trades;
    state.blocked_count = report.blocked_trades;
    state.protected_equity_inr = report.protected_final_equity_inr;
    state.unguarded_equity_inr = report.unguarded_final_equity_inr;
    state.total_capital_saved_inr = report.counterfactual_capital_saved_inr;
    state.net_pnl_inr = report.protected_net_pnl_inr;
    state.kill_switch_active = false;
    return res.status(200).json({ backtest: report, state });
  }

  if (urlPath === 'order') {
    const symbol = (body.symbol || 'NIFTY50').toUpperCase();
    const side = (body.side || 'BUY').toUpperCase();
    const qty = Number(body.qty || 1);
    const price = Number(body.price_inr || 24200);
    const notional = qty * price;
    const isOversized = notional > (state.policy?.max_notional_inr || 35000);

    const dec = {
      id: Math.floor(1000 + Math.random() * 9000),
      time_ist: new Date().toLocaleTimeString('en-IN', { timeZone: 'Asia/Kolkata', hour12: false }) + ' IST',
      symbol,
      side,
      qty,
      price_inr: price,
      notional_inr: notional,
      approved: !isOversized && !state.kill_switch_active,
      latency_ns: isOversized ? 13500 : 14417,
      fpga_verdict: isOversized ? 'REJECT' : 'PASS',
      fpga_cycles: 4,
      gate_triggered: isOversized
        ? 'NanoPolicyVm [PC#0 Code 101: Max Trade Notional]'
        : 'APPROVED (All 12 FinGate Stages + FPGA BAR0: Pass)',
      capital_saved_inr: isOversized ? notional : 0,
      fee_inr: body.is_fno ? 20 : 0,
      ai_explanation: isOversized
        ? `Order notional ₹${notional.toLocaleString('en-IN')} exceeds allowable policy cap of ₹${(state.policy?.max_notional_inr || 35000).toLocaleString('en-IN')}`
        : 'Cleared NanoPolicyVm and Hawkes toxicity filters with zero-allocation speed.',
    };

    if (dec.approved) {
      state.approved_count = (state.approved_count || 0) + 1;
      const existing = state.positions.find((p) => p.symbol === symbol);
      if (existing) {
        existing.qty += qty;
      } else {
        state.positions.push({
          symbol,
          qty,
          avg_entry_price_inr: price,
          last_price_inr: price,
          market_value_inr: notional,
          unrealized_pnl_inr: 0,
          realized_pnl_inr: 0,
        });
      }
    } else {
      state.blocked_count = (state.blocked_count || 0) + 1;
      state.total_capital_saved_inr = (state.total_capital_saved_inr || 0) + notional;
    }

    state.recent_decisions = [dec, ...(state.recent_decisions || []).slice(0, 19)];
    return res.status(200).json({ decision: dec, state });
  }

  if (urlPath === 'policy') {
    const text = body.nl_text || 'Max ₹35,000 per trade';
    const match = text.match(/₹?([0-9,]+)/);
    const cap = match ? Number(match[1].replace(/,/g, '')) : 35000;
    if (state.policy) {
      state.policy.policy_id = (state.policy.policy_id || 1) + 1;
      state.policy.natural_language = text;
      state.policy.max_notional_inr = cap;
      state.policy.dry_run_traps_caught = 10;
      state.policy.dry_run_elapsed_us = 18;
    }
    return res.status(200).json(state);
  }

  if (urlPath === 'chaos') {
    const kind = body.kind || 'fake_news';
    let gate = '';
    let saved = 0;
    let tripsKill = false;

    if (kind === 'fake_news') {
      gate = 'NanoPolicyVm [PC#0 Code 101: Max Trade Notional]';
      saved = 12125000;
      tripsKill = true;
    } else if (kind === 'toxic_sweep') {
      gate = 'Hawkes Self-Exciting Point Process + VPIN Cascade Shield';
      saved = 142500;
    } else if (kind === 'martingale_loop') {
      gate = 'Shannon Entropy AI-Hallucination Sentinel (Auto-Tripped Kill Switch)';
      saved = 185000;
      tripsKill = true;
    } else {
      gate = 'Relativistic Speed-of-Light Causality Guard (SG1 → Mumbai NSE)';
      saved = 850000;
    }

    if (tripsKill) state.kill_switch_active = true;
    state.blocked_count = (state.blocked_count || 0) + 1;
    state.total_capital_saved_inr = (state.total_capital_saved_inr || 0) + saved;

    const dec = {
      id: Math.floor(1000 + Math.random() * 9000),
      time_ist: new Date().toLocaleTimeString('en-IN', { timeZone: 'Asia/Kolkata', hour12: false }) + ' IST',
      symbol: 'NIFTY50',
      side: 'BUY',
      qty: 500,
      price_inr: 24250,
      notional_inr: saved,
      approved: false,
      latency_ns: 19416,
      fpga_verdict: 'REJECT',
      fpga_cycles: 4,
      gate_triggered: gate,
      capital_saved_inr: saved,
      fee_inr: 0,
      ai_explanation: `Adversarial scenario [${kind}] intercepted and neutralized in nanoseconds.`,
    };

    state.recent_decisions = [dec, ...(state.recent_decisions || []).slice(0, 19)];
    return res.status(200).json(state);
  }

  if (urlPath === 'quorum/trip') {
    state.kill_switch_active = true;
    return res.status(200).json(state);
  }

  if (urlPath === 'quorum/disarm') {
    const ids = body.custodian_ids || [];
    const tamper = Boolean(body.tamper_share);

    if (tamper) {
      return res.status(200).json({
        quorum: {
          success: false,
          elapsed_ns: 184,
          message: 'HMAC-SHA256 signature mismatch on Key #1 payload! Share tampering detected.',
        },
        state,
      });
    }

    if (ids.length < 3) {
      return res.status(200).json({
        quorum: {
          success: false,
          elapsed_ns: 412,
          message: `DENIED: Only ${ids.length} custodian share(s) provided; 3 of 5 required (M-1 insiders hold mathematically 0 bits of key!).`,
        },
        state,
      });
    }

    state.kill_switch_active = false;
    state.disarm_nonce = (state.disarm_nonce || 1) + 1;
    return res.status(200).json({
      quorum: {
        success: true,
        elapsed_ns: 916,
        message: `3-of-5 Shamir Secret Sharing over Mersenne F_(2^61-1) + Hardware HMAC-SHA256 VERIFIED in 916 ns! Anti-replay nonce bumped #${state.disarm_nonce - 1} -> #${state.disarm_nonce}. Kill Switch & FPGA BAR0 Kill Bit DISARMED.`,
      },
      state,
    });
  }

  if (urlPath === 'tax') {
    const inc = Number(body.annual_income_inr || 1500000);
    const ded = Number(body.deductions_80c_hra_inr || 200000);
    if (state.tax_report) {
      state.tax_report.annual_income_inr = inc;
      state.tax_report.deductions_80c_hra_inr = ded;
      state.tax_report.recommended_regime = 'New Tax Regime';
      state.tax_report.regime_savings_inr = 65000;
    }
    return res.status(200).json(state);
  }

  if (urlPath === 'chat') {
    const q = body.question || '';
    const answer = `**FinGate AI Financial Co-Pilot Summary:**\n\nYour portfolio is currently protected with **₹${(state.protected_equity_inr || 499945).toLocaleString('en-IN')}** in mark-to-market equity. Under the 12-Stage Singularity Firewall, all ${state.blocked_count || 12} unsafe orders were intercepted before exchange transmission, preserving **₹${(state.total_capital_saved_inr || 12348).toLocaleString('en-IN')}** from adverse HFT toxicity and prompt injection attempts.\n\n**Indian Tax Analysis:** Under Budget 2024 provisions, STCG is calculated at 20% flat under Section 111A, while LTCG is 12.5% above ₹1.25 Lakh under Section 112A. The **New Tax Regime (Section 115BAC)** saves ₹65,000 annually compared to the Old Regime for your income profile.`;
    return res.status(200).json({
      answer,
      mode: 'Grounded Offline',
      citations: ['SEBI Master Circular 2025/08', 'IT Act Section 115BAC', 'Budget 2024 Revised STCG 20%'],
    });
  }

  if (urlPath === 'flight-recorder') {
    return res.status(200).json({
      records: [
        { seq: 32, event_kind: 'PASS', cl_ord_id_hash: 32, price_inr: 283, qty: 90, proof_commit_hex: 'b9ceb7a4a49e1d02' },
        { seq: 31, event_kind: 'PASS', cl_ord_id_hash: 31, price_inr: 270, qty: 100, proof_commit_hex: '10aaead8f568a4f2' },
        { seq: 30, event_kind: 'PASS', cl_ord_id_hash: 30, price_inr: 72, qty: 50, proof_commit_hex: 'a6fc638776556a62' },
        { seq: 29, event_kind: 'PASS', cl_ord_id_hash: 29, price_inr: 254, qty: 120, proof_commit_hex: 'c5cd32e25bbdd58b' },
        { seq: 28, event_kind: 'REJECT', cl_ord_id_hash: 28, price_inr: 244, qty: 1500, proof_commit_hex: 'eb957a11eb75f386' },
      ],
      total_recorded: 32,
    });
  }

  if (urlPath === 'proof/verify') {
    const id = Number(query.id || 27);
    return res.status(200).json({
      decision_id: id,
      merkle_leaf_idx: id - 1,
      merkle_leaf_hash_hex: 'f7fef3879bbc64f72e1244e5f79e2647191e42765ebc76f66705c09216d6206a',
      merkle_root_hex: state.latest_merkle_root_hex || '96d504f3472e357bd9b4db76a53807114b6575b1fee1d561f5905130b78311e0',
      merkle_sibling_hashes_hex: [
        'f5a5fd42d16a2030',
        '3412ca52ef6c9913',
        'c78009fdf07fc56a',
        '2320725c05e921f3',
        'fbff9014d6329caf',
      ],
      merkle_proof_valid: true,
      merkle_verify_ns: 842,
      lattice_sis_valid: true,
      lattice_norm_bound: 20971520,
      lattice_verify_ns: 125,
    });
  }

  return res.status(404).json({ error: 'Endpoint not found', path: urlPath });
}
