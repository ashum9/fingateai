//! Month 1, Week 1: Zero-Copy FIX 4.2/4.4/5.0 Wire Scanner & Streaming TCP Defragmenter.
//!
//! Provides:
//! 1. `FixWireView<'a>`: Zero-heap-allocation, stack-resident tag-value scanner over raw
//!    FIX wire bytes (`SOH = 0x01` or pipe `'|'` delimited).
//! 2. Exact `BeginString (8)`, `BodyLength (9)`, and modulo-256 `CheckSum (10)` verification
//!    implementing FIX 4.4 Vol 2 Garbled Message isolation (Rule `R25` / Invariant `I1`).
//! 3. `FixFrameBuilder`: Fast wire encoder with optional fault injection (`corrupt_checksum`,
//!    `corrupt_body_length`) for chaos testing.
//! 4. `FixTcpDefragmenter`: Streaming ring/accumulator buffer that reconstructs complete
//!    FIX frames across fragmented TCP `recv()` calls and Nagle-coalesced multi-message packets.

use std::mem::MaybeUninit;
use std::str;

pub const SOH: u8 = 0x01;
pub const MAX_INLINE_TAGS: usize = 64;

/// A zero-copy byte-offset slice representing a single `tag=value` field inside a wire buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TagSlice {
    pub tag: u32,
    pub val_start: u16,
    pub val_len: u16,
}

/// Classification of wire-level framing errors per FIX 4.4 Vol 2 ("Garbled Messages").
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WireFramingError {
    EmptyFrame,
    MissingBeginString,
    MissingBodyLength,
    InvalidBodyLengthValue,
    BodyLengthMismatch { declared: usize, actual: usize },
    MissingCheckSum,
    InvalidCheckSumFormat,
    CheckSumMismatch { declared: u8, computed: u8 },
    MalformedTagField,
    TooManyTags,
}

/// Phase C2: Zero-copy Simple Binary Encoding (SBE) Little-Endian frame view
/// (CME iLink 3 / Binance Spot SBE compatible, zero heap allocations).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SbeWireView<'a> {
    pub block_length: u16,
    pub template_id: u16,
    pub schema_id: u16,
    pub version: u16,
    pub body: &'a [u8],
}

impl<'a> SbeWireView<'a> {
    pub const HEADER_BYTES: usize = 8;

    #[inline(always)]
    pub fn parse(raw: &'a [u8]) -> Option<Self> {
        if raw.len() < Self::HEADER_BYTES {
            return None;
        }
        let block_length = u16::from_le_bytes([raw[0], raw[1]]);
        let template_id = u16::from_le_bytes([raw[2], raw[3]]);
        let schema_id = u16::from_le_bytes([raw[4], raw[5]]);
        let version = u16::from_le_bytes([raw[6], raw[7]]);
        if raw.len() < Self::HEADER_BYTES + (block_length as usize) {
            return None;
        }
        Some(Self {
            block_length,
            template_id,
            schema_id,
            version,
            body: &raw[Self::HEADER_BYTES..],
        })
    }

    #[inline(always)]
    pub fn read_u64_le(&self, offset: usize) -> Option<u64> {
        let end = offset.checked_add(8)?;
        if end > self.body.len() {
            return None;
        }
        let slice = &self.body[offset..end];
        Some(u64::from_le_bytes([
            slice[0], slice[1], slice[2], slice[3], slice[4], slice[5], slice[6], slice[7],
        ]))
    }

    #[inline(always)]
    pub fn read_i64_le(&self, offset: usize) -> Option<i64> {
        self.read_u64_le(offset).map(|v| v as i64)
    }
}

/// Zero-heap-allocation parsed view over a validated FIX wire frame (`&'a [u8]`).
/// Uses uninitialized stack slots (`MaybeUninit<TagSlice>`) and O(1) hot-tag direct indices
/// for all 8 order-entry fields (`1, 11, 34, 35, 38, 44, 54, 55`).
#[derive(Clone)]
pub struct FixWireView<'a> {
    raw: &'a [u8],
    delim: u8,
    tags: [MaybeUninit<TagSlice>; MAX_INLINE_TAGS],
    tag_count: usize,
    idx_msg_type: u8,
    idx_msg_seq: u8,
    idx_cl_ord_id: u8,
    idx_account: u8,
    idx_order_qty: u8,
    idx_price: u8,
    idx_side: u8,
    idx_symbol: u8,
    pub body_length: usize,
    pub checksum: u8,
}

/// Track I5: Direct single-pass fused SIMD + SWAR extracted FIX 4.4 order fields (`0` TagSlice writes, `0` allocs).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FastFixOrderFields<'a> {
    pub msg_type: &'a [u8],
    pub msg_seq_num: u64,
    pub cl_ord_id: &'a [u8],
    pub symbol: &'a [u8],
    pub account: &'a [u8],
    pub side: u8,
    pub order_qty: u64,
    pub price_whole: u64,
    pub body_length: usize,
    pub checksum: u8,
}

impl<'a> std::fmt::Debug for FixWireView<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FixWireView")
            .field("delim", &self.delim)
            .field("tag_count", &self.tag_count)
            .field("body_length", &self.body_length)
            .field("checksum", &self.checksum)
            .finish()
    }
}

impl<'a> FixWireView<'a> {
    /// Parse and validate a single raw FIX wire frame (`SOH` `0x01` or `'|'` delimited)
    /// using SIMD-accelerated checksum + single-pass pointer tag scanning with zero heap allocations.
    #[inline]
    pub fn parse_and_validate(raw: &'a [u8]) -> Result<Self, WireFramingError> {
        let len = raw.len();
        if len == 0 {
            return Err(WireFramingError::EmptyFrame);
        }

        // 1. First tag must be 8=FIX...
        if len < 12 || &raw[0..6] != b"8=FIX." {
            return Err(WireFramingError::MissingBeginString);
        }

        // O(1) delimiter detection without scanning the full buffer upfront
        let (delim, first_delim) = if unsafe { *raw.get_unchecked(9) } == SOH
            || unsafe { *raw.get_unchecked(9) } == b'|'
        {
            (unsafe { *raw.get_unchecked(9) }, 9usize)
        } else {
            let mut found = None;
            let search_end = len.min(24);
            let mut idx = 6;
            while idx < search_end {
                let b = unsafe { *raw.get_unchecked(idx) };
                if b == SOH || b == b'|' {
                    found = Some((b, idx));
                    break;
                }
                idx += 1;
            }
            found.ok_or(WireFramingError::MissingBeginString)?
        };

        // 2. Second tag must be 9=<BodyLength>
        let tag9_start = first_delim + 1;
        if tag9_start + 2 >= len || &raw[tag9_start..tag9_start + 2] != b"9=" {
            return Err(WireFramingError::MissingBodyLength);
        }
        let mut cursor_9 = tag9_start + 2;
        let mut declared_body_len: usize = 0;
        let mut saw_digit_9 = false;
        while cursor_9 < len {
            let b = unsafe { *raw.get_unchecked(cursor_9) };
            if b == delim {
                break;
            }
            let d = b.wrapping_sub(b'0');
            if d > 9 {
                return Err(WireFramingError::InvalidBodyLengthValue);
            }
            declared_body_len = declared_body_len.wrapping_mul(10).wrapping_add(d as usize);
            saw_digit_9 = true;
            cursor_9 += 1;
        }
        if cursor_9 >= len {
            return Err(WireFramingError::MissingBodyLength);
        }
        if !saw_digit_9 {
            return Err(WireFramingError::InvalidBodyLengthValue);
        }
        let second_delim = cursor_9;

        // 3. Final tag must be 10=<3-digit CheckSum><delim>
        if unsafe { *raw.get_unchecked(len - 1) } != delim || len < second_delim + 1 + 7 {
            return Err(WireFramingError::MissingCheckSum);
        }
        let trailer_start = len - 7;
        if unsafe { *raw.get_unchecked(trailer_start - 1) } != delim
            || &raw[trailer_start..trailer_start + 3] != b"10="
        {
            return Err(WireFramingError::MissingCheckSum);
        }

        let actual_body_len = trailer_start - (second_delim + 1);
        if actual_body_len != declared_body_len {
            return Err(WireFramingError::BodyLengthMismatch {
                declared: declared_body_len,
                actual: actual_body_len,
            });
        }

        let c0 = unsafe { *raw.get_unchecked(trailer_start + 3) }.wrapping_sub(b'0');
        let c1 = unsafe { *raw.get_unchecked(trailer_start + 4) }.wrapping_sub(b'0');
        let c2 = unsafe { *raw.get_unchecked(trailer_start + 5) }.wrapping_sub(b'0');
        if c0 > 9 || c1 > 9 || c2 > 9 {
            return Err(WireFramingError::InvalidCheckSumFormat);
        }
        let declared_cs = c0.wrapping_mul(100).wrapping_add(c1.wrapping_mul(10)).wrapping_add(c2);

        // 4. Gap 3 (E3): Single-Pass Fused SIMD Checksum + Delimiter/Equals Bitmask Indexing
        //    Computes modulo-256 CheckSum AND extracts '=' & SOH bitmasks in ONE L1 cache pass
        //    for frames <= 512 bytes (99.99% of low-latency orders), jumping straight from tag to tag
        //    via hardware `trailing_zeros()` without scanning value bytes!
        let mut tags = [MaybeUninit::<TagSlice>::uninit(); MAX_INLINE_TAGS];

        // Tag 0 (8=BeginString) & Tag 1 (9=BodyLength) already validated
        tags[0].write(TagSlice {
            tag: 8,
            val_start: 2,
            val_len: (first_delim - 2) as u16,
        });
        tags[1].write(TagSlice {
            tag: 9,
            val_start: (tag9_start + 2) as u16,
            val_len: (second_delim - (tag9_start + 2)) as u16,
        });
        let mut tag_count = 2usize;
        let mut idx_msg_type = u8::MAX;
        let mut idx_msg_seq = u8::MAX;
        let mut idx_cl_ord_id = u8::MAX;
        let mut idx_account = u8::MAX;
        let mut idx_order_qty = u8::MAX;
        let mut idx_price = u8::MAX;
        let mut idx_side = u8::MAX;
        let mut idx_symbol = u8::MAX;

        let base = raw.as_ptr();
        let body_start = second_delim + 1;

        if trailer_start <= 512 {
            let mut eq_words = [MaybeUninit::<u64>::uninit(); 8];
            let mut delim_words = [MaybeUninit::<u64>::uninit(); 8];
            let eq_ptr = eq_words.as_mut_ptr() as *mut u64;
            let delim_ptr = delim_words.as_mut_ptr() as *mut u64;
            let computed_cs = unsafe {
                simd_fused_checksum_and_masks(base, trailer_start, delim, eq_ptr, delim_ptr)
            };
            if computed_cs != declared_cs {
                return Err(WireFramingError::CheckSumMismatch {
                    declared: declared_cs,
                    computed: computed_cs,
                });
            }

            let num_words = (trailer_start + 63) >> 6;
            let mut cursor = body_start;
            let mut d_w = cursor >> 6;
            let mut e_w = d_w;
            let init_shift = cursor & 63;
            let mut d_mask = if d_w < num_words {
                unsafe { *delim_ptr.add(d_w) & (!0u64 << init_shift) }
            } else {
                0
            };
            let mut e_mask = if e_w < num_words {
                unsafe { *eq_ptr.add(e_w) & (!0u64 << init_shift) }
            } else {
                0
            };

            while cursor < trailer_start {
                if tag_count >= MAX_INLINE_TAGS - 1 {
                    return Err(WireFramingError::TooManyTags);
                }

                // Register-resident 1-cycle delimiter jump (no memory loads within 64B word)
                while d_mask == 0 {
                    d_w += 1;
                    if d_w >= num_words {
                        return Err(WireFramingError::MalformedTagField);
                    }
                    d_mask = unsafe { *delim_ptr.add(d_w) };
                }
                let delim_pos = (d_w << 6) + d_mask.trailing_zeros() as usize;
                d_mask &= d_mask - 1;
                if delim_pos >= trailer_start {
                    return Err(WireFramingError::MalformedTagField);
                }

                // Register-resident 1-cycle '=' jump
                while e_mask == 0 {
                    e_w += 1;
                    if e_w >= num_words {
                        return Err(WireFramingError::MalformedTagField);
                    }
                    e_mask = unsafe { *eq_ptr.add(e_w) };
                }
                let eq_pos = (e_w << 6) + e_mask.trailing_zeros() as usize;
                if eq_pos <= cursor || eq_pos >= delim_pos {
                    return Err(WireFramingError::MalformedTagField);
                }

                let tag_num = unsafe { parse_tag_num_fast(base, cursor, eq_pos - cursor) }
                    .ok_or(WireFramingError::MalformedTagField)?;

                // Cache all 8 hot order-entry tag slot indices in O(1)
                match tag_num {
                    35 if idx_msg_type == u8::MAX => idx_msg_type = tag_count as u8,
                    34 if idx_msg_seq == u8::MAX => idx_msg_seq = tag_count as u8,
                    11 if idx_cl_ord_id == u8::MAX => idx_cl_ord_id = tag_count as u8,
                    1 if idx_account == u8::MAX => idx_account = tag_count as u8,
                    38 if idx_order_qty == u8::MAX => idx_order_qty = tag_count as u8,
                    44 if idx_price == u8::MAX => idx_price = tag_count as u8,
                    54 if idx_side == u8::MAX => idx_side = tag_count as u8,
                    55 if idx_symbol == u8::MAX => idx_symbol = tag_count as u8,
                    _ => {}
                }

                let val_start = eq_pos + 1;
                unsafe {
                    tags.get_unchecked_mut(tag_count).write(TagSlice {
                        tag: tag_num,
                        val_start: val_start as u16,
                        val_len: (delim_pos - val_start) as u16,
                    });
                }
                tag_count += 1;
                cursor = delim_pos + 1;

                // Advance e_mask past delim_pos (skips any '=' inside value safely)
                let next_w = cursor >> 6;
                if next_w == e_w {
                    e_mask &= !0u64 << (cursor & 63);
                } else {
                    e_w = next_w;
                    e_mask = if e_w < num_words {
                        unsafe { *eq_ptr.add(e_w) & (!0u64 << (cursor & 63)) }
                    } else {
                        0
                    };
                }
            }
        } else {
            // Fallback for oversized FIX frames (> 512 bytes)
            let computed_cs = simd_checksum_mod256(&raw[..trailer_start], delim);
            if computed_cs != declared_cs {
                return Err(WireFramingError::CheckSumMismatch {
                    declared: declared_cs,
                    computed: computed_cs,
                });
            }

            let mut cursor = body_start;
            while cursor < trailer_start {
                if tag_count >= MAX_INLINE_TAGS - 1 {
                    return Err(WireFramingError::TooManyTags);
                }
                let mut tag_num: u32 = 0;
                let tag_start = cursor;
                while cursor < trailer_start {
                    let b = unsafe { *base.add(cursor) };
                    if b == b'=' {
                        break;
                    }
                    let d = b.wrapping_sub(b'0');
                    if d > 9 {
                        return Err(WireFramingError::MalformedTagField);
                    }
                    tag_num = tag_num.wrapping_mul(10).wrapping_add(d as u32);
                    cursor += 1;
                }
                if cursor == tag_start || cursor >= trailer_start {
                    return Err(WireFramingError::MalformedTagField);
                }
                let val_start = cursor + 1;
                let mut end_pos = val_start;
                while end_pos < trailer_start && unsafe { *base.add(end_pos) } != delim {
                    end_pos += 1;
                }
                if end_pos >= trailer_start {
                    return Err(WireFramingError::MalformedTagField);
                }
                match tag_num {
                    35 if idx_msg_type == u8::MAX => idx_msg_type = tag_count as u8,
                    34 if idx_msg_seq == u8::MAX => idx_msg_seq = tag_count as u8,
                    11 if idx_cl_ord_id == u8::MAX => idx_cl_ord_id = tag_count as u8,
                    1 if idx_account == u8::MAX => idx_account = tag_count as u8,
                    38 if idx_order_qty == u8::MAX => idx_order_qty = tag_count as u8,
                    44 if idx_price == u8::MAX => idx_price = tag_count as u8,
                    54 if idx_side == u8::MAX => idx_side = tag_count as u8,
                    55 if idx_symbol == u8::MAX => idx_symbol = tag_count as u8,
                    _ => {}
                }
                unsafe {
                    tags.get_unchecked_mut(tag_count).write(TagSlice {
                        tag: tag_num,
                        val_start: val_start as u16,
                        val_len: (end_pos - val_start) as u16,
                    });
                }
                tag_count += 1;
                cursor = end_pos + 1;
            }
        }

        // Write validated Tag 10 (CheckSum) directly without re-scanning
        unsafe {
            tags.get_unchecked_mut(tag_count).write(TagSlice {
                tag: 10,
                val_start: (trailer_start + 3) as u16,
                val_len: 3,
            });
        }
        tag_count += 1;

        Ok(Self {
            raw,
            delim,
            tags,
            tag_count,
            idx_msg_type,
            idx_msg_seq,
            idx_cl_ord_id,
            idx_account,
            idx_order_qty,
            idx_price,
            idx_side,
            idx_symbol,
            body_length: declared_body_len,
            checksum: declared_cs,
        })
    }

    /// Track I5: Ultra-fast fused SIMD + SWAR single-pass FIX 4.4 order extractor.
    /// Validates `8=`, `9=`, and modulo-256 `10=` CheckSum AND extracts core order fields directly
    /// without building a 512-byte `TagSlice[64]` array (`0` heap allocs!).
    #[inline]
    pub fn parse_order_fused_swar(raw: &'a [u8]) -> Result<FastFixOrderFields<'a>, WireFramingError> {
        let len = raw.len();
        if len < 20 || len > 512 {
            // Fall back cleanly to general `parse_and_validate` for tiny/oversized frames
            let v = Self::parse_and_validate(raw)?;
            return Ok(FastFixOrderFields {
                msg_type: v.get_raw(35).unwrap_or(&[]),
                msg_seq_num: v.msg_seq_num().unwrap_or(0),
                cl_ord_id: v.get_raw(11).unwrap_or(&[]),
                symbol: v.get_raw(55).unwrap_or(&[]),
                account: v.get_raw(1).unwrap_or(&[]),
                side: v.get_raw(54).and_then(|s| s.first().copied()).unwrap_or(0),
                order_qty: v.get_u64(38).unwrap_or(0),
                price_whole: v.get_u64(44).unwrap_or(0),
                body_length: v.body_length,
                checksum: v.checksum,
            });
        }

        if raw[0] != b'8' || raw[1] != b'=' {
            return Err(WireFramingError::MissingBeginString);
        }
        let (delim, first_delim) = if unsafe { *raw.get_unchecked(9) } == SOH
            || unsafe { *raw.get_unchecked(9) } == b'|'
        {
            (unsafe { *raw.get_unchecked(9) }, 9usize)
        } else {
            let mut found = None;
            let search_end = len.min(24);
            let mut idx = 6;
            while idx < search_end {
                let b = unsafe { *raw.get_unchecked(idx) };
                if b == SOH || b == b'|' {
                    found = Some((b, idx));
                    break;
                }
                idx += 1;
            }
            found.ok_or(WireFramingError::MissingBeginString)?
        };

        let tag9_start = first_delim + 1;
        if tag9_start + 3 >= len || raw[tag9_start] != b'9' || raw[tag9_start + 1] != b'=' {
            return Err(WireFramingError::MissingBodyLength);
        }
        let mut cursor_9 = tag9_start + 2;
        let mut declared_body_len: usize = 0;
        let mut saw_digit_9 = false;
        while cursor_9 < len {
            let b = unsafe { *raw.get_unchecked(cursor_9) };
            if b == delim {
                break;
            }
            let d = b.wrapping_sub(b'0');
            if d > 9 {
                return Err(WireFramingError::InvalidBodyLengthValue);
            }
            declared_body_len = declared_body_len.wrapping_mul(10).wrapping_add(d as usize);
            saw_digit_9 = true;
            cursor_9 += 1;
        }
        if cursor_9 >= len {
            return Err(WireFramingError::MissingBodyLength);
        }
        if !saw_digit_9 {
            return Err(WireFramingError::InvalidBodyLengthValue);
        }
        let second_delim = cursor_9;

        let trailer_start = len - 7;
        if trailer_start <= second_delim
            || raw[trailer_start] != b'1'
            || raw[trailer_start + 1] != b'0'
            || raw[trailer_start + 2] != b'='
        {
            return Err(WireFramingError::MissingCheckSum);
        }
        let actual_body_len = trailer_start - (second_delim + 1);
        if declared_body_len != actual_body_len {
            return Err(WireFramingError::BodyLengthMismatch {
                declared: declared_body_len,
                actual: actual_body_len,
            });
        }

        let c0 = raw[trailer_start + 3].wrapping_sub(b'0');
        let c1 = raw[trailer_start + 4].wrapping_sub(b'0');
        let c2 = raw[trailer_start + 5].wrapping_sub(b'0');
        if c0 > 9 || c1 > 9 || c2 > 9 {
            return Err(WireFramingError::InvalidCheckSumFormat);
        }
        let declared_cs = c0.wrapping_mul(100).wrapping_add(c1.wrapping_mul(10)).wrapping_add(c2);

        let base = raw.as_ptr();
        let mut eq_words = [MaybeUninit::<u64>::uninit(); 8];
        let mut delim_words = [MaybeUninit::<u64>::uninit(); 8];
        let eq_ptr = eq_words.as_mut_ptr() as *mut u64;
        let delim_ptr = delim_words.as_mut_ptr() as *mut u64;
        let computed_cs = unsafe {
            simd_fused_checksum_and_masks(base, trailer_start, delim, eq_ptr, delim_ptr)
        };
        if computed_cs != declared_cs {
            return Err(WireFramingError::CheckSumMismatch {
                declared: declared_cs,
                computed: computed_cs,
            });
        }

        let mut msg_type: &'a [u8] = &[];
        let mut msg_seq_num: u64 = 0;
        let mut cl_ord_id: &'a [u8] = &[];
        let mut symbol: &'a [u8] = &[];
        let mut account: &'a [u8] = &[];
        let mut side: u8 = 0;
        let mut order_qty: u64 = 0;
        let mut price_whole: u64 = 0;

        let num_words = (trailer_start + 63) >> 6;
        let mut cursor = second_delim + 1;
        let mut d_w = cursor >> 6;
        let mut e_w = d_w;
        let init_shift = cursor & 63;
        let mut d_mask = if d_w < num_words {
            unsafe { *delim_ptr.add(d_w) & (!0u64 << init_shift) }
        } else {
            0
        };
        let mut e_mask = if e_w < num_words {
            unsafe { *eq_ptr.add(e_w) & (!0u64 << init_shift) }
        } else {
            0
        };

        while cursor < trailer_start {
            while d_mask == 0 {
                d_w += 1;
                if d_w >= num_words {
                    return Err(WireFramingError::MalformedTagField);
                }
                d_mask = unsafe { *delim_ptr.add(d_w) };
            }
            let delim_pos = (d_w << 6) + d_mask.trailing_zeros() as usize;
            d_mask &= d_mask - 1;
            if delim_pos >= trailer_start {
                return Err(WireFramingError::MalformedTagField);
            }

            while e_mask == 0 {
                e_w += 1;
                if e_w >= num_words {
                    return Err(WireFramingError::MalformedTagField);
                }
                e_mask = unsafe { *eq_ptr.add(e_w) };
            }
            let eq_pos = (e_w << 6) + e_mask.trailing_zeros() as usize;
            if eq_pos <= cursor || eq_pos >= delim_pos {
                return Err(WireFramingError::MalformedTagField);
            }

            let tag_num = unsafe { parse_tag_num_fast(base, cursor, eq_pos - cursor) }
                .ok_or(WireFramingError::MalformedTagField)?;
            let val = unsafe { raw.get_unchecked(eq_pos + 1..delim_pos) };

            match tag_num {
                35 => msg_type = val,
                34 => msg_seq_num = parse_u64_swar(val).unwrap_or(0),
                11 => cl_ord_id = val,
                55 => symbol = val,
                1 => account = val,
                54 => side = val.first().copied().unwrap_or(0),
                38 => order_qty = parse_u64_swar(val).unwrap_or(0),
                44 => price_whole = parse_u64_swar_integer_part(val),
                _ => {}
            }

            cursor = delim_pos + 1;
            let next_w = cursor >> 6;
            if next_w == e_w {
                e_mask &= !0u64 << (cursor & 63);
            } else {
                e_w = next_w;
                e_mask = if e_w < num_words {
                    unsafe { *eq_ptr.add(e_w) & (!0u64 << (cursor & 63)) }
                } else {
                    0
                };
            }
        }

        Ok(FastFixOrderFields {
            msg_type,
            msg_seq_num,
            cl_ord_id,
            symbol,
            account,
            side,
            order_qty,
            price_whole,
            body_length: declared_body_len,
            checksum: declared_cs,
        })
    }

    #[inline(always)]
    fn get_str_at(&self, idx: usize) -> Option<&'a str> {
        let ts = unsafe { self.tags.get_unchecked(idx).assume_init() };
        let start = ts.val_start as usize;
        let end = start + ts.val_len as usize;
        str::from_utf8(unsafe { self.raw.get_unchecked(start..end) }).ok()
    }

    /// O(1) direct index lookup helper for all 8 cached hot order-entry tags.
    #[inline(always)]
    fn hot_tag_idx(&self, tag: u32) -> u8 {
        match tag {
            11 => self.idx_cl_ord_id,
            35 => self.idx_msg_type,
            34 => self.idx_msg_seq,
            38 => self.idx_order_qty,
            44 => self.idx_price,
            54 => self.idx_side,
            55 => self.idx_symbol,
            1 => self.idx_account,
            _ => u8::MAX,
        }
    }

    /// Look up raw bytes for a tag with O(1) fast path for all 8 core order-entry tags (skips UTF-8 check).
    #[inline]
    pub fn get_raw(&self, tag: u32) -> Option<&'a [u8]> {
        let hot = self.hot_tag_idx(tag);
        if hot != u8::MAX {
            let ts = unsafe { self.tags.get_unchecked(hot as usize).assume_init() };
            let start = ts.val_start as usize;
            return Some(unsafe { self.raw.get_unchecked(start..start + ts.val_len as usize) });
        }
        for i in 0..self.tag_count {
            let ts = unsafe { self.tags.get_unchecked(i).assume_init() };
            if ts.tag == tag {
                let start = ts.val_start as usize;
                return Some(unsafe { self.raw.get_unchecked(start..start + ts.val_len as usize) });
            }
        }
        None
    }

    /// Look up a tag value as `&'a str` with O(1) fast path for all 8 core order-entry tags.
    #[inline]
    pub fn get_str(&self, tag: u32) -> Option<&'a str> {
        let hot = self.hot_tag_idx(tag);
        if hot != u8::MAX {
            return self.get_str_at(hot as usize);
        }
        for i in 0..self.tag_count {
            let ts = unsafe { self.tags.get_unchecked(i).assume_init() };
            if ts.tag == tag {
                let start = ts.val_start as usize;
                let end = start + ts.val_len as usize;
                return str::from_utf8(unsafe { self.raw.get_unchecked(start..end) }).ok();
            }
        }
        None
    }

    /// Look up an integer tag value (`34=MsgSeqNum`, `38=OrderQty`, `44=Price`, etc.) via SWAR fast parser.
    #[inline]
    pub fn get_u64(&self, tag: u32) -> Option<u64> {
        let hot = self.hot_tag_idx(tag);
        if hot != u8::MAX {
            let ts = unsafe { self.tags.get_unchecked(hot as usize).assume_init() };
            let start = ts.val_start as usize;
            let end = start + ts.val_len as usize;
            return parse_u64_swar(unsafe { self.raw.get_unchecked(start..end) });
        }
        for i in 0..self.tag_count {
            let ts = unsafe { self.tags.get_unchecked(i).assume_init() };
            if ts.tag == tag {
                let start = ts.val_start as usize;
                let end = start + ts.val_len as usize;
                return parse_u64_swar(unsafe { self.raw.get_unchecked(start..end) });
            }
        }
        None
    }

    /// Look up a boolean FIX flag (`'Y'` -> `Some(true)`, `'N'` -> `Some(false)`).
    #[inline]
    pub fn get_bool(&self, tag: u32) -> Option<bool> {
        self.get_str(tag).and_then(|s| match s {
            "Y" | "true" => Some(true),
            "N" | "false" => Some(false),
            _ => None,
        })
    }

    #[inline(always)]
    pub fn msg_type(&self) -> Option<&'a str> {
        if self.idx_msg_type != u8::MAX {
            self.get_str_at(self.idx_msg_type as usize)
        } else {
            None
        }
    }

    #[inline(always)]
    pub fn msg_seq_num(&self) -> Option<u64> {
        if self.idx_msg_seq != u8::MAX {
            let ts = unsafe { self.tags.get_unchecked(self.idx_msg_seq as usize).assume_init() };
            let start = ts.val_start as usize;
            let end = start + ts.val_len as usize;
            parse_u64_ascii(unsafe { self.raw.get_unchecked(start..end) })
        } else {
            None
        }
    }

    #[inline]
    pub fn tag_count(&self) -> usize {
        self.tag_count
    }

    #[inline]
    pub fn delimiter(&self) -> u8 {
        self.delim
    }

    /// Phase D2: Zero-copy repeating group iterator (e.g. `count_tag = 555 (NoLegs)`,
    /// `delim_tag = 600 (LegSymbol)` or `count_tag = 453 (NoPartyIDs)`, `delim_tag = 448 (PartyID)`).
    /// Yields each group entry's delimiter value without allocating a `Vec`.
    #[inline]
    pub fn repeating_group_iter(&self, count_tag: u32, entry_delim_tag: u32) -> RepeatingGroupIter<'_, 'a> {
        let mut expected = 0usize;
        let mut start_idx = self.tag_count;
        for i in 0..self.tag_count {
            let ts = unsafe { self.tags.get_unchecked(i).assume_init() };
            if ts.tag == count_tag {
                let s = ts.val_start as usize;
                let e = s + ts.val_len as usize;
                expected = parse_u64_ascii(unsafe { self.raw.get_unchecked(s..e) }).unwrap_or(0) as usize;
                start_idx = i + 1;
                break;
            }
        }
        RepeatingGroupIter {
            view: self,
            entry_delim_tag,
            cursor: start_idx,
            remaining: expected,
        }
    }
}

/// Zero-allocation iterator over FIX 4.4 / 5.0 repeating group entries.
pub struct RepeatingGroupIter<'v, 'a> {
    view: &'v FixWireView<'a>,
    entry_delim_tag: u32,
    cursor: usize,
    remaining: usize,
}

impl<'v, 'a> Iterator for RepeatingGroupIter<'v, 'a> {
    type Item = &'a str;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 {
            return None;
        }
        while self.cursor < self.view.tag_count {
            let idx = self.cursor;
            self.cursor += 1;
            let ts = unsafe { self.view.tags.get_unchecked(idx).assume_init() };
            if ts.tag == self.entry_delim_tag {
                self.remaining -= 1;
                return self.view.get_str_at(idx);
            }
        }
        self.remaining = 0;
        None
    }
}

/// Phase C2: SIMD-accelerated modulo-256 byte sum over raw SOH wire bytes (reusable across Kill Switch & Wire Engine).
#[inline(always)]
pub fn simd_sum_mod256(data: &[u8]) -> u8 {
    simd_checksum_mod256(data, SOH)
}

/// SIMD-accelerated modulo-256 checksum normalizing `delim` (`'|'` -> `SOH`).
#[inline(always)]
pub fn simd_checksum_mod256(data: &[u8], delim: u8) -> u8 {
    #[cfg(target_arch = "aarch64")]
    {
        unsafe { neon_checksum_mod256(data, delim) }
    }
    #[cfg(target_arch = "x86_64")]
    {
        if is_x86_feature_detected!("avx2") {
            return unsafe { avx2_checksum_mod256(data, delim) };
        }
        scalar_checksum_mod256(data, delim)
    }
    #[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
    {
        scalar_checksum_mod256(data, delim)
    }
}

#[cfg(not(target_arch = "aarch64"))]
#[inline(always)]
fn scalar_checksum_mod256(data: &[u8], delim: u8) -> u8 {
    let mut sum: u8 = 0;
    if delim == SOH {
        for &b in data {
            sum = sum.wrapping_add(b);
        }
    } else {
        for &b in data {
            sum = sum.wrapping_add(if b == delim { SOH } else { b });
        }
    }
    sum
}

#[cfg(target_arch = "aarch64")]
#[inline(always)]
unsafe fn neon_checksum_mod256(data: &[u8], delim: u8) -> u8 {
    use core::arch::aarch64::*;
    let len = data.len();
    let mut ptr = data.as_ptr();
    let end = ptr.add(len);
    let mut acc = vdupq_n_u8(0);

    if delim == SOH {
        while ptr.add(16) <= end {
            let chunk = vld1q_u8(ptr);
            acc = vaddq_u8(acc, chunk);
            ptr = ptr.add(16);
        }
        let mut sum = vaddvq_u8(acc);
        while ptr < end {
            sum = sum.wrapping_add(*ptr);
            ptr = ptr.add(1);
        }
        sum
    } else {
        let v_delim = vdupq_n_u8(delim);
        let v_soh = vdupq_n_u8(SOH);
        while ptr.add(16) <= end {
            let chunk = vld1q_u8(ptr);
            let mask = vceqq_u8(chunk, v_delim);
            let norm = vbslq_u8(mask, v_soh, chunk);
            acc = vaddq_u8(acc, norm);
            ptr = ptr.add(16);
        }
        let mut sum = vaddvq_u8(acc);
        while ptr < end {
            let b = *ptr;
            sum = sum.wrapping_add(if b == delim { SOH } else { b });
            ptr = ptr.add(1);
        }
        sum
    }
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
unsafe fn avx2_checksum_mod256(data: &[u8], delim: u8) -> u8 {
    use core::arch::x86_64::*;
    let len = data.len();
    let mut ptr = data.as_ptr();
    let end = ptr.add(len);
    let mut acc = _mm256_setzero_si256();
    if delim == SOH {
        while ptr.add(32) <= end {
            let chunk = _mm256_loadu_si256(ptr as *const __m256i);
            acc = _mm256_add_epi8(acc, chunk);
            ptr = ptr.add(32);
        }
        let mut lanes = [0u8; 32];
        _mm256_storeu_si256(lanes.as_mut_ptr() as *mut __m256i, acc);
        let mut sum: u8 = 0;
        for &b in &lanes {
            sum = sum.wrapping_add(b);
        }
        while ptr < end {
            sum = sum.wrapping_add(*ptr);
            ptr = ptr.add(1);
        }
        sum
    } else {
        let v_delim = _mm256_set1_epi8(delim as i8);
        let v_soh = _mm256_set1_epi8(SOH as i8);
        while ptr.add(32) <= end {
            let chunk = _mm256_loadu_si256(ptr as *const __m256i);
            let mask = _mm256_cmpeq_epi8(chunk, v_delim);
            let norm = _mm256_blendv_epi8(chunk, v_soh, mask);
            acc = _mm256_add_epi8(acc, norm);
            ptr = ptr.add(32);
        }
        let mut lanes = [0u8; 32];
        _mm256_storeu_si256(lanes.as_mut_ptr() as *mut __m256i, acc);
        let mut sum: u8 = 0;
        for &b in &lanes {
            sum = sum.wrapping_add(b);
        }
        while ptr < end {
            let b = *ptr;
            sum = sum.wrapping_add(if b == delim { SOH } else { b });
            ptr = ptr.add(1);
        }
        sum
    }
}

/// Phase C2: SIMD-accelerated byte scan (`NEON` on ARM64, `AVX2` on x86_64, scalar tail).
#[inline(always)]
pub fn simd_find_byte(needle: u8, haystack: &[u8], start: usize) -> Option<usize> {
    #[cfg(target_arch = "aarch64")]
    {
        unsafe { neon_find_byte(needle, haystack, start) }
    }
    #[cfg(target_arch = "x86_64")]
    {
        if is_x86_feature_detected!("avx2") {
            return unsafe { avx2_find_byte(needle, haystack, start) };
        }
        memchr_byte(needle, haystack, start)
    }
    #[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
    {
        memchr_byte(needle, haystack, start)
    }
}

#[cfg(target_arch = "aarch64")]
#[inline(always)]
unsafe fn neon_find_byte(needle: u8, haystack: &[u8], start: usize) -> Option<usize> {
    use core::arch::aarch64::*;
    let len = haystack.len();
    let mut i = start;
    let v_needle = vdupq_n_u8(needle);
    while i + 16 <= len {
        let chunk = vld1q_u8(haystack.as_ptr().add(i));
        let cmp = vceqq_u8(chunk, v_needle);
        if vmaxvq_u8(cmp) != 0 {
            // Find exact matching lane inside this 16-byte chunk
            let lo = vgetq_lane_u64(vreinterpretq_u64_u8(cmp), 0);
            if lo != 0 {
                return Some(i + (lo.trailing_zeros() >> 3) as usize);
            }
            let hi = vgetq_lane_u64(vreinterpretq_u64_u8(cmp), 1);
            return Some(i + 8 + (hi.trailing_zeros() >> 3) as usize);
        }
        i += 16;
    }
    while i < len {
        if *haystack.get_unchecked(i) == needle {
            return Some(i);
        }
        i += 1;
    }
    None
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
unsafe fn avx2_find_byte(needle: u8, haystack: &[u8], start: usize) -> Option<usize> {
    use core::arch::x86_64::*;
    let len = haystack.len();
    let mut i = start;
    let v_needle = _mm256_set1_epi8(needle as i8);
    while i + 32 <= len {
        let chunk = _mm256_loadu_si256(haystack.as_ptr().add(i) as *const __m256i);
        let mask = _mm256_movemask_epi8(_mm256_cmpeq_epi8(chunk, v_needle)) as u32;
        if mask != 0 {
            return Some(i + mask.trailing_zeros() as usize);
        }
        i += 32;
    }
    while i < len {
        if *haystack.get_unchecked(i) == needle {
            return Some(i);
        }
        i += 1;
    }
    None
}

#[cfg(not(target_arch = "aarch64"))]
#[inline(always)]
fn memchr_byte(needle: u8, haystack: &[u8], start: usize) -> Option<usize> {
    let mut i = start;
    while i < haystack.len() {
        if haystack[i] == needle {
            return Some(i);
        }
        i += 1;
    }
    None
}

/// Track I5: SWAR 8-Digit Parallel ASCII-to-`u64` converter (0 branches for 8-digit chunks!).
/// Validates all 8 bytes are ASCII `'0'..='9'` with zero cross-byte carry/borrow artifacts and
/// converts 8 digits in 3 parallel integer multiplies (`~2 ns` vs byte-by-byte loop).
#[inline(always)]
pub fn parse_u64_swar(bytes: &[u8]) -> Option<u64> {
    let len = bytes.len();
    if len == 0 {
        return None;
    }
    if len <= 8 {
        let mut buf = [b'0'; 8];
        unsafe {
            std::ptr::copy_nonoverlapping(bytes.as_ptr(), buf.as_mut_ptr().add(8 - len), len);
        }
        let w = u64::from_le_bytes(buf);
        const HI_NIBBLE_MASK: u64 = 0xF0F0_F0F0_F0F0_F0F0;
        const ASCII_ZERO_HI: u64 = 0x3030_3030_3030_3030;
        const ADD_SIX: u64 = 0x0606_0606_0606_0606;
        if (w & HI_NIBBLE_MASK) != ASCII_ZERO_HI
            || ((w.wrapping_add(ADD_SIX)) & HI_NIBBLE_MASK) != ASCII_ZERO_HI
        {
            return None;
        }
        let mut v = w & 0x0F0F_0F0F_0F0F_0F0F;
        v = ((v.wrapping_mul(10)).wrapping_add(v >> 8)) & 0x00FF_00FF_00FF_00FF;
        v = ((v.wrapping_mul(100)).wrapping_add(v >> 16)) & 0x0000_FFFF_0000_FFFF;
        return Some((v & 0xFFFF_FFFF).wrapping_mul(10_000).wrapping_add(v >> 32));
    }
    // > 8 digits: SWAR first 8, then remaining digits cleanly
    let mut acc = parse_u64_swar(&bytes[..8])?;
    for &b in &bytes[8..] {
        let d = b.wrapping_sub(b'0');
        if d > 9 {
            return None;
        }
        acc = acc.wrapping_mul(10).wrapping_add(d as u64);
    }
    Some(acc)
}

/// Parse whole integer portion of a FIX decimal price (e.g. `"58250.75"` -> `58250`) via SWAR.
#[inline(always)]
fn parse_u64_swar_integer_part(bytes: &[u8]) -> u64 {
    let mut end = bytes.len();
    for (i, &b) in bytes.iter().enumerate() {
        if b == b'.' {
            end = i;
            break;
        }
    }
    parse_u64_swar(&bytes[..end]).unwrap_or(0)
}

#[inline(always)]
fn parse_u64_ascii(bytes: &[u8]) -> Option<u64> {
    parse_u64_swar(bytes)
}

/// Builder for wire-level FIX 4.4 frames (`8=FIX.4.4\x019=...\x0110=...\x01`).
#[derive(Debug, Clone, Default)]
pub struct FixFrameBuilder {
    body_buf: Vec<u8>,
}

impl FixFrameBuilder {
    pub fn new() -> Self {
        Self {
            body_buf: Vec::with_capacity(256),
        }
    }

    pub fn clear(&mut self) {
        self.body_buf.clear();
    }

    pub fn push_str(&mut self, tag: u32, val: &str) -> &mut Self {
        push_u32_ascii(&mut self.body_buf, tag);
        self.body_buf.push(b'=');
        self.body_buf.extend_from_slice(val.as_bytes());
        self.body_buf.push(SOH);
        self
    }

    pub fn push_u64(&mut self, tag: u32, val: u64) -> &mut Self {
        push_u32_ascii(&mut self.body_buf, tag);
        self.body_buf.push(b'=');
        push_u64_ascii(&mut self.body_buf, val);
        self.body_buf.push(SOH);
        self
    }

    pub fn push_bool(&mut self, tag: u32, val: bool) -> &mut Self {
        self.push_str(tag, if val { "Y" } else { "N" })
    }

    /// Encode complete SOH-delimited FIX 4.4 wire bytes with optional chaos fault injection.
    pub fn finish_soh_bytes(
        &self,
        corrupt_checksum: bool,
        corrupt_body_length: bool,
    ) -> Vec<u8> {
        let mut body_len = self.body_buf.len();
        if corrupt_body_length {
            body_len += 7;
        }
        let mut out = Vec::with_capacity(32 + self.body_buf.len());
        out.extend_from_slice(b"8=FIX.4.4\x019=");
        push_u64_ascii(&mut out, body_len as u64);
        out.push(SOH);
        out.extend_from_slice(&self.body_buf);

        let mut sum: u32 = 0;
        for &b in &out {
            sum += b as u32;
        }
        let mut cs = (sum % 256) as u8;
        if corrupt_checksum {
            cs = cs.wrapping_add(42);
        }
        out.extend_from_slice(b"10=");
        out.push(b'0' + (cs / 100));
        out.push(b'0' + ((cs / 10) % 10));
        out.push(b'0' + (cs % 10));
        out.push(SOH);
        out
    }

    /// Encode pipe-delimited string (`8=FIX.4.4|9=...|10=...|`) for human/JSON logs.
    pub fn finish_pipe_string(
        &self,
        corrupt_checksum: bool,
        corrupt_body_length: bool,
    ) -> String {
        let bytes = self.finish_soh_bytes(corrupt_checksum, corrupt_body_length);
        bytes
            .into_iter()
            .map(|b| if b == SOH { '|' } else { b as char })
            .collect()
    }
}

#[inline(always)]
fn push_u32_ascii(buf: &mut Vec<u8>, mut n: u32) {
    if n == 0 {
        buf.push(b'0');
        return;
    }
    let mut tmp = [0u8; 10];
    let mut i = 10;
    while n > 0 {
        i -= 1;
        tmp[i] = b'0' + (n % 10) as u8;
        n /= 10;
    }
    buf.extend_from_slice(&tmp[i..]);
}

#[inline(always)]
fn push_u64_ascii(buf: &mut Vec<u8>, mut n: u64) {
    if n == 0 {
        buf.push(b'0');
        return;
    }
    let mut tmp = [0u8; 20];
    let mut i = 20;
    while n > 0 {
        i -= 1;
        tmp[i] = b'0' + (n % 10) as u8;
        n /= 10;
    }
    buf.extend_from_slice(&tmp[i..]);
}

/// Outcome of extracting a frame from a streaming TCP buffer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DefragmentedFrame {
    /// A complete raw frame extracted from the wire (may be valid or garbled).
    RawFrame(Vec<u8>),
}

/// Streaming TCP frame accumulator that handles half-frame segmentation and Nagle coalescing.
/// Extracts individual FIX messages bounded by `8=FIX.` and trailer `\x0110=XYZ\x01`.
#[derive(Debug, Default)]
pub struct FixTcpDefragmenter {
    buf: Vec<u8>,
}

impl FixTcpDefragmenter {
    pub fn new() -> Self {
        Self {
            buf: Vec::with_capacity(4096),
        }
    }

    /// Feed newly received TCP bytes and drain all complete FIX wire frames.
    pub fn feed(&mut self, chunk: &[u8]) -> Vec<Vec<u8>> {
        self.buf.extend_from_slice(chunk);
        let mut frames = Vec::new();

        loop {
            if self.buf.len() < 18 {
                break;
            }
            let delim = if simd_find_byte(SOH, &self.buf, 0).is_some() { SOH } else { b'|' };
            // Locate trailer `<delim>10=XYZ<delim>` using SIMD delimiter jumps
            let mut found_end: Option<usize> = None;
            let mut search_pos = 0usize;
            while let Some(i) = simd_find_byte(delim, &self.buf, search_pos) {
                if i + 8 > self.buf.len() {
                    break;
                }
                if &self.buf[i + 1..i + 4] == b"10=" && self.buf[i + 7] == delim {
                    found_end = Some(i + 8);
                    break;
                }
                search_pos = i + 1;
            }

            if let Some(end_idx) = found_end {
                let frame = self.buf[..end_idx].to_vec();
                self.buf.drain(..end_idx);
                frames.push(frame);
            } else {
                break;
            }
        }

        frames
    }

    pub fn buffered_bytes(&self) -> usize {
        self.buf.len()
    }
}

/// Gap 3 (E3): Fast unrolled ASCII FIX tag number parser (99% of FIX tags are 1–4 digits).
#[inline(always)]
unsafe fn parse_tag_num_fast(base: *const u8, start: usize, len: usize) -> Option<u32> {
    match len {
        2 => {
            let d0 = (*base.add(start)).wrapping_sub(b'0');
            let d1 = (*base.add(start + 1)).wrapping_sub(b'0');
            if d0 > 9 || d1 > 9 {
                return None;
            }
            Some((d0 as u32) * 10 + (d1 as u32))
        }
        1 => {
            let d0 = (*base.add(start)).wrapping_sub(b'0');
            if d0 > 9 {
                return None;
            }
            Some(d0 as u32)
        }
        3 => {
            let d0 = (*base.add(start)).wrapping_sub(b'0');
            let d1 = (*base.add(start + 1)).wrapping_sub(b'0');
            let d2 = (*base.add(start + 2)).wrapping_sub(b'0');
            if d0 > 9 || d1 > 9 || d2 > 9 {
                return None;
            }
            Some((d0 as u32) * 100 + (d1 as u32) * 10 + (d2 as u32))
        }
        4 => {
            let d0 = (*base.add(start)).wrapping_sub(b'0');
            let d1 = (*base.add(start + 1)).wrapping_sub(b'0');
            let d2 = (*base.add(start + 2)).wrapping_sub(b'0');
            let d3 = (*base.add(start + 3)).wrapping_sub(b'0');
            if d0 > 9 || d1 > 9 || d2 > 9 || d3 > 9 {
                return None;
            }
            Some((d0 as u32) * 1000 + (d1 as u32) * 100 + (d2 as u32) * 10 + (d3 as u32))
        }
        0 => None,
        _ => {
            let mut acc: u32 = 0;
            for i in 0..len {
                let d = (*base.add(start + i)).wrapping_sub(b'0');
                if d > 9 {
                    return None;
                }
                acc = acc.wrapping_mul(10).wrapping_add(d as u32);
            }
            Some(acc)
        }
    }
}

/// Gap 3 (E3): Single-Pass Fused SIMD CheckSum + `'='` & `delim` 64-byte Bitmask Extractor.
///
/// Processes 64 bytes per iteration on `aarch64` NEON (`vpaddq_u8` 64-bit movemask = 1 GPR transfer!)
/// or 32 bytes per iteration on `x86_64` AVX2, computing modulo-256 checksum AND delimiter bitmasks
/// in ONE single L1 cache load pass!
#[inline(always)]
unsafe fn simd_fused_checksum_and_masks(
    base: *const u8,
    len: usize,
    delim: u8,
    eq_ptr: *mut u64,
    delim_ptr: *mut u64,
) -> u8 {
    let mut offset = 0usize;
    let mut word_idx = 0usize;

    #[cfg(target_arch = "aarch64")]
    {
        use core::arch::aarch64::*;
        const BIT_WEIGHTS: [u8; 16] = [1, 2, 4, 8, 16, 32, 64, 128, 1, 2, 4, 8, 16, 32, 64, 128];
        let v_weights = vld1q_u8(BIT_WEIGHTS.as_ptr());
        let v_eq = vdupq_n_u8(b'=');
        let v_delim = vdupq_n_u8(delim);
        let v_soh = vdupq_n_u8(SOH);
        let mut v_sum = vdupq_n_u8(0);

        while offset + 64 <= len {
            let p = base.add(offset);
            let c0 = vld1q_u8(p);
            let c1 = vld1q_u8(p.add(16));
            let c2 = vld1q_u8(p.add(32));
            let c3 = vld1q_u8(p.add(48));

            let d0 = vceqq_u8(c0, v_delim);
            let d1 = vceqq_u8(c1, v_delim);
            let d2 = vceqq_u8(c2, v_delim);
            let d3 = vceqq_u8(c3, v_delim);

            if delim == SOH {
                let s01 = vaddq_u8(c0, c1);
                let s23 = vaddq_u8(c2, c3);
                v_sum = vaddq_u8(v_sum, vaddq_u8(s01, s23));
            } else {
                let a0 = vbslq_u8(d0, v_soh, c0);
                let a1 = vbslq_u8(d1, v_soh, c1);
                let a2 = vbslq_u8(d2, v_soh, c2);
                let a3 = vbslq_u8(d3, v_soh, c3);
                v_sum = vaddq_u8(v_sum, vaddq_u8(vaddq_u8(a0, a1), vaddq_u8(a2, a3)));
            }

            let dm0 = vpaddq_u8(vandq_u8(d0, v_weights), vandq_u8(d1, v_weights));
            let dm1 = vpaddq_u8(vandq_u8(d2, v_weights), vandq_u8(d3, v_weights));
            let dm2 = vpaddq_u8(dm0, dm1);
            let dm3 = vpaddq_u8(dm2, dm2);
            delim_ptr.add(word_idx).write(vgetq_lane_u64(vreinterpretq_u64_u8(dm3), 0));

            let e0 = vceqq_u8(c0, v_eq);
            let e1 = vceqq_u8(c1, v_eq);
            let e2 = vceqq_u8(c2, v_eq);
            let e3 = vceqq_u8(c3, v_eq);
            let em0 = vpaddq_u8(vandq_u8(e0, v_weights), vandq_u8(e1, v_weights));
            let em1 = vpaddq_u8(vandq_u8(e2, v_weights), vandq_u8(e3, v_weights));
            let em2 = vpaddq_u8(em0, em1);
            let em3 = vpaddq_u8(em2, em2);
            eq_ptr.add(word_idx).write(vgetq_lane_u64(vreinterpretq_u64_u8(em3), 0));

            offset += 64;
            word_idx += 1;
        }

        let mut rem_eq: u64 = 0;
        let mut rem_delim: u64 = 0;
        let mut bit_shift = 0u32;
        while offset + 16 <= len {
            let c = vld1q_u8(base.add(offset));
            let dc = vceqq_u8(c, v_delim);
            if delim == SOH {
                v_sum = vaddq_u8(v_sum, c);
            } else {
                v_sum = vaddq_u8(v_sum, vbslq_u8(dc, v_soh, c));
            }
            let dm = vandq_u8(dc, v_weights);
            let d_lo = vaddv_u8(vget_low_u8(dm)) as u64;
            let d_hi = vaddv_u8(vget_high_u8(dm)) as u64;
            rem_delim |= (d_lo | (d_hi << 8)) << bit_shift;

            let ec = vceqq_u8(c, v_eq);
            let em = vandq_u8(ec, v_weights);
            let e_lo = vaddv_u8(vget_low_u8(em)) as u64;
            let e_hi = vaddv_u8(vget_high_u8(em)) as u64;
            rem_eq |= (e_lo | (e_hi << 8)) << bit_shift;

            offset += 16;
            bit_shift += 16;
        }
        let mut cs = vaddvq_u8(v_sum);

        while offset < len {
            let b = *base.add(offset);
            cs = cs.wrapping_add(if b == delim { SOH } else { b });
            if b == delim {
                rem_delim |= 1u64 << bit_shift;
            } else if b == b'=' {
                rem_eq |= 1u64 << bit_shift;
            }
            offset += 1;
            bit_shift += 1;
        }
        if bit_shift > 0 && word_idx < 8 {
            delim_ptr.add(word_idx).write(rem_delim);
            eq_ptr.add(word_idx).write(rem_eq);
        }
        return cs;
    }

    #[cfg(all(target_arch = "x86_64", target_feature = "avx2"))]
    {
        use core::arch::x86_64::*;
        let v_eq = _mm256_set1_epi8(b'=' as i8);
        let v_delim = _mm256_set1_epi8(delim as i8);
        let v_soh = _mm256_set1_epi8(SOH as i8);
        let mut v_sum = _mm256_setzero_si256();

        while offset + 64 <= len {
            let p = base.add(offset);
            let c0 = _mm256_loadu_si256(p as *const __m256i);
            let c1 = _mm256_loadu_si256(p.add(32) as *const __m256i);
            let d0 = _mm256_cmpeq_epi8(c0, v_delim);
            let d1 = _mm256_cmpeq_epi8(c1, v_delim);
            if delim == SOH {
                v_sum = _mm256_add_epi8(v_sum, _mm256_add_epi8(c0, c1));
            } else {
                let a0 = _mm256_blendv_epi8(c0, v_soh, d0);
                let a1 = _mm256_blendv_epi8(c1, v_soh, d1);
                v_sum = _mm256_add_epi8(v_sum, _mm256_add_epi8(a0, a1));
            }
            let dm0 = _mm256_movemask_epi8(d0) as u32 as u64;
            let dm1 = _mm256_movemask_epi8(d1) as u32 as u64;
            delim_ptr.add(word_idx).write(dm0 | (dm1 << 32));

            let em0 = _mm256_movemask_epi8(_mm256_cmpeq_epi8(c0, v_eq)) as u32 as u64;
            let em1 = _mm256_movemask_epi8(_mm256_cmpeq_epi8(c1, v_eq)) as u32 as u64;
            eq_ptr.add(word_idx).write(em0 | (em1 << 32));

            offset += 64;
            word_idx += 1;
        }
        let mut cs: u8 = 0;
        let mut lane_buf = [0u8; 32];
        _mm256_storeu_si256(lane_buf.as_mut_ptr() as *mut __m256i, v_sum);
        for &b in &lane_buf {
            cs = cs.wrapping_add(b);
        }
        let mut rem_eq: u64 = 0;
        let mut rem_delim: u64 = 0;
        let mut bit_shift = 0u32;
        while offset < len {
            let b = *base.add(offset);
            cs = cs.wrapping_add(if b == delim { SOH } else { b });
            if b == delim {
                rem_delim |= 1u64 << bit_shift;
            } else if b == b'=' {
                rem_eq |= 1u64 << bit_shift;
            }
            offset += 1;
            bit_shift += 1;
        }
        if bit_shift > 0 && word_idx < 8 {
            delim_ptr.add(word_idx).write(rem_delim);
            eq_ptr.add(word_idx).write(rem_eq);
        }
        return cs;
    }

    #[cfg(not(any(
        target_arch = "aarch64",
        all(target_arch = "x86_64", target_feature = "avx2")
    )))]
    {
        let num_words = (len + 63) >> 6;
        for w in 0..num_words {
            delim_ptr.add(w).write(0);
            eq_ptr.add(w).write(0);
        }
        let mut cs: u8 = 0;
        while offset < len {
            let b = *base.add(offset);
            cs = cs.wrapping_add(if b == delim { SOH } else { b });
            let w = offset >> 6;
            let bit = offset & 63;
            if b == delim {
                *delim_ptr.add(w) |= 1u64 << bit;
            } else if b == b'=' {
                *eq_ptr.add(w) |= 1u64 << bit;
            }
            offset += 1;
        }
        let _ = word_idx;
        cs
    }
}
