//! Month 2, Week 3: CME iLink 3 Digital Twin (`CmeIlinkTwin`).
//!
//! Emulates CME Group iLink 3 SBE over TCP binary protocol:
//! 1. SBE Transport Framing: `MessageSize` (u16) + `EncodingType` (u16).
//! 2. Protocol Header: `BlockLength` (u16), `TemplateID` (u16), `SchemaID` (u16), `Version` (u16).
//! 3. Two-phase session establishment state machine:
//!    - Phase 1: `Negotiate (500)` -> `NegotiationResponse (501)`
//!    - Phase 2: `Establish (503)` -> `EstablishmentAck (504)`
//! 4. In-flight sequence tracking and `RetransmitRequest (508)` support.

// CME iLink 3 SBE over TCP definitions

pub const CME_SCHEMA_ID: u16 = 8;
pub const CME_VERSION: u16 = 1;

pub const TEMPLATE_NEGOTIATE: u16 = 500;
pub const TEMPLATE_NEGOTIATION_RESPONSE: u16 = 501;
pub const TEMPLATE_ESTABLISH: u16 = 503;
pub const TEMPLATE_ESTABLISHMENT_ACK: u16 = 504;
pub const TEMPLATE_SEQUENCE: u16 = 506;
pub const TEMPLATE_RETRANSMIT_REQUEST: u16 = 508;
pub const TEMPLATE_RETRANSMISSION: u16 = 509;
pub const TEMPLATE_NEW_ORDER_SINGLE: u16 = 514;
pub const TEMPLATE_EXECUTION_REPORT: u16 = 515;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CmeSessionState {
    Disconnected,
    Negotiated { uuid: [u8; 16] },
    Established { uuid: [u8; 16] },
}

pub struct CmeIlinkTwin {
    pub state: CmeSessionState,
    pub next_sender_seq: u32,
    pub next_target_seq: u32,
    pub session_uuid: [u8; 16],
    pub keep_alive_interval_ms: u32,
    pub retransmit_requests_served: u32,
}

impl CmeIlinkTwin {
    pub fn new(session_uuid: [u8; 16]) -> Self {
        Self {
            state: CmeSessionState::Disconnected,
            next_sender_seq: 1,
            next_target_seq: 1,
            session_uuid,
            keep_alive_interval_ms: 10_000,
            retransmit_requests_served: 0,
        }
    }

    /// Process a raw CME iLink 3 binary packet. Returns response binary packet if applicable.
    pub fn handle_inbound_packet(&mut self, packet: &[u8]) -> Option<Vec<u8>> {
        if packet.len() < 12 {
            return None; // Framing error: must have 4 bytes framing + 8 bytes SBE header
        }

        let msg_size = u16::from_le_bytes(packet[0..2].try_into().unwrap()) as usize;
        let _encoding_type = u16::from_le_bytes(packet[2..4].try_into().unwrap());
        if packet.len() < 4 + msg_size {
            return None; // Incomplete packet
        }

        let sbe_slice = &packet[4..4 + msg_size];
        let _block_length = u16::from_le_bytes(sbe_slice[0..2].try_into().unwrap());
        let template_id = u16::from_le_bytes(sbe_slice[2..4].try_into().unwrap());

        match template_id {
            TEMPLATE_NEGOTIATE => {
                // Negotiate: sbe_slice[8..24] is UUID
                if sbe_slice.len() < 24 {
                    return None;
                }
                let incoming_uuid: [u8; 16] = sbe_slice[8..24].try_into().unwrap();
                if incoming_uuid != self.session_uuid {
                    // Reject UUID mismatch
                    return Some(self.encode_negotiation_response(incoming_uuid, 1)); // 1 = Rejected
                }

                self.state = CmeSessionState::Negotiated { uuid: incoming_uuid };
                Some(self.encode_negotiation_response(incoming_uuid, 0)) // 0 = Negotiated
            }
            TEMPLATE_ESTABLISH => {
                if let CmeSessionState::Negotiated { uuid } = self.state {
                    let next_seq = if sbe_slice.len() >= 28 {
                        u32::from_le_bytes(sbe_slice[24..28].try_into().unwrap())
                    } else {
                        1
                    };
                    self.next_target_seq = next_seq;
                    self.state = CmeSessionState::Established { uuid };
                    Some(self.encode_establishment_ack(uuid, self.next_sender_seq))
                } else {
                    None // Must negotiate before establishing
                }
            }
            TEMPLATE_RETRANSMIT_REQUEST => {
                if let CmeSessionState::Established { uuid } = self.state {
                    self.retransmit_requests_served += 1;
                    let from_seq = if sbe_slice.len() >= 28 {
                        u32::from_le_bytes(sbe_slice[24..28].try_into().unwrap())
                    } else {
                        1
                    };
                    let count = if sbe_slice.len() >= 30 {
                        u16::from_le_bytes(sbe_slice[28..30].try_into().unwrap())
                    } else {
                        1
                    };
                    Some(self.encode_retransmission(uuid, from_seq, count))
                } else {
                    None
                }
            }
            TEMPLATE_NEW_ORDER_SINGLE => {
                if let CmeSessionState::Established { .. } = self.state {
                    self.next_target_seq += 1;
                    let order_id = 999888u64;
                    let resp = self.encode_execution_report_ack(order_id);
                    Some(resp)
                } else {
                    None
                }
            }
            _ => None,
        }
    }

    fn encode_negotiation_response(&self, uuid: [u8; 16], status: u8) -> Vec<u8> {
        let body_len = 16 + 1; // UUID(16) + Status(1)
        let sbe_len = 8 + body_len;
        let mut out = Vec::with_capacity(4 + sbe_len);

        // Framing: MsgSize(u16) + EncodingType(u16)
        out.extend_from_slice(&(sbe_len as u16).to_le_bytes());
        out.extend_from_slice(&0xEB50u16.to_le_bytes()); // CME SBE encoding type

        // SBE Header: block_length, template_id, schema_id, version
        out.extend_from_slice(&(body_len as u16).to_le_bytes());
        out.extend_from_slice(&TEMPLATE_NEGOTIATION_RESPONSE.to_le_bytes());
        out.extend_from_slice(&CME_SCHEMA_ID.to_le_bytes());
        out.extend_from_slice(&CME_VERSION.to_le_bytes());

        // Body
        out.extend_from_slice(&uuid);
        out.push(status);
        out
    }

    fn encode_establishment_ack(&mut self, uuid: [u8; 16], next_seq: u32) -> Vec<u8> {
        let body_len = 16 + 4 + 4; // UUID(16) + NextSeq(4) + KeepAlive(4)
        let sbe_len = 8 + body_len;
        let mut out = Vec::with_capacity(4 + sbe_len);

        out.extend_from_slice(&(sbe_len as u16).to_le_bytes());
        out.extend_from_slice(&0xEB50u16.to_le_bytes());

        out.extend_from_slice(&(body_len as u16).to_le_bytes());
        out.extend_from_slice(&TEMPLATE_ESTABLISHMENT_ACK.to_le_bytes());
        out.extend_from_slice(&CME_SCHEMA_ID.to_le_bytes());
        out.extend_from_slice(&CME_VERSION.to_le_bytes());

        out.extend_from_slice(&uuid);
        out.extend_from_slice(&next_seq.to_le_bytes());
        out.extend_from_slice(&self.keep_alive_interval_ms.to_le_bytes());
        self.next_sender_seq += 1;
        out
    }

    fn encode_retransmission(&self, uuid: [u8; 16], from_seq: u32, count: u16) -> Vec<u8> {
        let body_len = 16 + 4 + 2;
        let sbe_len = 8 + body_len;
        let mut out = Vec::with_capacity(4 + sbe_len);

        out.extend_from_slice(&(sbe_len as u16).to_le_bytes());
        out.extend_from_slice(&0xEB50u16.to_le_bytes());

        out.extend_from_slice(&(body_len as u16).to_le_bytes());
        out.extend_from_slice(&TEMPLATE_RETRANSMISSION.to_le_bytes());
        out.extend_from_slice(&CME_SCHEMA_ID.to_le_bytes());
        out.extend_from_slice(&CME_VERSION.to_le_bytes());

        out.extend_from_slice(&uuid);
        out.extend_from_slice(&from_seq.to_le_bytes());
        out.extend_from_slice(&count.to_le_bytes());
        out
    }

    fn encode_execution_report_ack(&mut self, order_id: u64) -> Vec<u8> {
        let body_len = 8 + 4;
        let sbe_len = 8 + body_len;
        let mut out = Vec::with_capacity(4 + sbe_len);

        out.extend_from_slice(&(sbe_len as u16).to_le_bytes());
        out.extend_from_slice(&0xEB50u16.to_le_bytes());

        out.extend_from_slice(&(body_len as u16).to_le_bytes());
        out.extend_from_slice(&TEMPLATE_EXECUTION_REPORT.to_le_bytes());
        out.extend_from_slice(&CME_SCHEMA_ID.to_le_bytes());
        out.extend_from_slice(&CME_VERSION.to_le_bytes());

        out.extend_from_slice(&order_id.to_le_bytes());
        out.extend_from_slice(&self.next_sender_seq.to_le_bytes());
        self.next_sender_seq += 1;
        out
    }
}
