// Bounded STUN client transaction — the RFC 5389 §7.2.1 retransmission
// schedule and the rule for matching a response to the request that earned it.
//
// I/O-free and clock-free: every decision is a pure function of the state and
// a caller-supplied `now`. The pump owns the socket and the clock; this owns
// when a retransmission is due and when a transaction has failed.
//
// WHY A TRANSACTION AND NOT A SEND. STUN runs over UDP, so a request that is
// never answered is indistinguishable from one that was never delivered. The
// only way to tell is to retransmit on a schedule and eventually give up, and
// that schedule is normative: getting it wrong is how a client either floods a
// server or reports a failure the network would have recovered from.
//
//   Transmissions            Rc = 7
//   Initial RTO              500 ms
//   Backoff                  RTO doubles after each transmission
//   Wait after the last      Rm × RTO = 16 × 500 ms
//
// which puts the total at 39.5 s — the figure §7.2.1 gives, and the reason the
// last interval is not simply another doubling.

/// Initial retransmission timeout (RFC 5389 §7.2.1 recommends 500 ms).
pub const STUN_RTO_MS: u64 = 500;
/// Transmissions before a transaction is abandoned (`Rc`).
pub const STUN_RC: u8 = 7;
/// Multiplier on the final wait (`Rm`), so a last-moment response still counts.
pub const STUN_RM: u64 = 16;

/// What the pump should do for this transaction right now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StunTxnAction {
    /// Put the request on the wire; `attempt` is 1-based.
    Send { attempt: u8 },
    /// Nothing is due yet.
    Wait,
    /// Every transmission went unanswered and the final wait elapsed.
    TimedOut,
}

/// One in-flight Binding transaction.
///
/// `Copy` and 24 bytes: a client that later gathers several candidates holds an
/// array of these, not a heap.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StunTxn {
    /// The 96-bit transaction id, echoed by the server in its response.
    pub id: [u8; 12],
    /// Transmissions already made.
    pub sent: u8,
    /// When the next action falls due.
    pub due_ms: u64,
    /// 1 once a response has been accepted; the transaction is then inert.
    pub done: u8,
}

impl StunTxn {
    /// Arm a transaction. The first transmission is due immediately, because a
    /// client with something to ask has no reason to wait before asking.
    #[must_use]
    pub fn start(id: [u8; 12], now_ms: u64) -> Self {
        Self {
            id,
            sent: 0,
            due_ms: now_ms,
            done: 0,
        }
    }

    /// The interval to wait after the transmission numbered `sent` (1-based).
    ///
    /// Doubling, except after the LAST transmission: there the wait is `Rm ×
    /// RTO` rather than another doubling, which is what makes the total 39.5 s
    /// instead of 63.5 s. Saturating, so a pathological `sent` cannot overflow
    /// the shift.
    #[must_use]
    pub fn interval_ms(sent: u8) -> u64 {
        if sent >= STUN_RC {
            return STUN_RM * STUN_RTO_MS;
        }
        let shift = u32::from(sent.saturating_sub(1)).min(16);
        STUN_RTO_MS.saturating_mul(1u64 << shift)
    }

    /// What to do at `now_ms`. Pure: calling it twice at the same instant
    /// returns the same answer and changes nothing.
    #[must_use]
    pub fn poll(&self, now_ms: u64) -> StunTxnAction {
        if self.done != 0 {
            return StunTxnAction::Wait;
        }
        if now_ms < self.due_ms {
            return StunTxnAction::Wait;
        }
        if self.sent >= STUN_RC {
            return StunTxnAction::TimedOut;
        }
        StunTxnAction::Send {
            attempt: self.sent + 1,
        }
    }

    /// Record that the transmission `poll` asked for has gone out, and arm the
    /// next deadline.
    pub fn sent_at(&mut self, now_ms: u64) {
        if self.done != 0 || self.sent >= STUN_RC {
            return;
        }
        self.sent += 1;
        self.due_ms = now_ms.saturating_add(Self::interval_ms(self.sent));
    }

    /// Does `id` identify this transaction?
    ///
    /// Compared in full and without an early return. The transaction id is the
    /// only thing tying a datagram to a request — anyone can send a STUN
    /// response to an open UDP port, and accepting one on a partial match is
    /// how a client is told its address by someone who was never asked.
    #[must_use]
    pub fn matches(&self, id: &[u8]) -> bool {
        if id.len() != self.id.len() {
            return false;
        }
        let mut diff = 0u8;
        let mut i = 0;
        while i < self.id.len() {
            diff |= self.id[i] ^ id[i];
            i += 1;
        }
        diff == 0
    }

    /// Accept a response, ending the transaction. Returns false if it was
    /// already finished, so a duplicate response is not counted twice.
    pub fn accept(&mut self) -> bool {
        if self.done != 0 {
            return false;
        }
        self.done = 1;
        true
    }

    /// Has this transaction finished, either way?
    #[must_use]
    pub fn is_finished(&self, now_ms: u64) -> bool {
        self.done != 0 || matches!(self.poll(now_ms), StunTxnAction::TimedOut)
    }
}

/// Derive a transaction id from a counter and a seed.
///
/// Not cryptographic, and it does not need to be: RFC 5389 §3 wants the id
/// unpredictable enough that an off-path attacker cannot forge a response, and
/// this module's own defence is that it also checks the source address and the
/// FINGERPRINT. What it MUST be is unique across concurrent transactions, which
/// a counter guarantees exactly.
///
/// The seed lets a deployment vary the sequence between instances; a graph that
/// leaves it zero gets a usable, repeatable client.
#[must_use]
pub fn stun_txn_id(counter: u64, seed: u64) -> [u8; 12] {
    let mut id = [0u8; 12];
    // Golden-ratio odd multiplier: cheap avalanche so consecutive counters do
    // not produce ids differing in one bit.
    let mixed = counter
        .wrapping_mul(0x9E37_79B9_7F4A_7C15)
        .wrapping_add(seed);
    id[..8].copy_from_slice(&mixed.to_be_bytes());
    id[8..].copy_from_slice(&(counter as u32).to_be_bytes());
    id
}

// ---- the result a client reports -------------------------------------------

/// What a finished transaction learned. Appended, never renumbered: these
/// cross a channel as one byte.
pub const STUN_RES_OK: u8 = 0;
/// Every transmission went unanswered.
pub const STUN_RES_TIMEOUT: u8 = 1;
/// The server answered, and its answer was an error response.
pub const STUN_RES_ERROR: u8 = 2;
/// The server answered successfully but carried no address this client could
/// read — a success with nothing in it is not a reflexive address.
pub const STUN_RES_NO_ADDRESS: u8 = 3;

/// Wire length of a result record.
pub const STUN_RESULT_LEN: usize = 1 + 4 + 2 + 2;

/// `[status:u8][ip:4 BE][port:u16 LE][code:u16 LE]`.
///
/// The address is big-endian because that is how it travels in STUN and in
/// every other address on this repo's datagram surface; the two integers are
/// little-endian because that is how records are read here. Mixing the two is
/// deliberate and stated rather than tidied: re-encoding the address would
/// mean a consumer that logs it has to undo the tidying.
///
/// `code` is the STUN error code when `status` is [`STUN_RES_ERROR`], and 0
/// otherwise. `ip`/`port` are 0 unless `status` is [`STUN_RES_OK`].
#[must_use]
pub fn write_stun_result(
    status: u8,
    ip_be: [u8; 4],
    port: u16,
    code: u16,
    out: &mut [u8],
) -> Option<usize> {
    if out.len() < STUN_RESULT_LEN {
        return None;
    }
    out[0] = status;
    out[1..5].copy_from_slice(&ip_be);
    out[5..7].copy_from_slice(&port.to_le_bytes());
    out[7..9].copy_from_slice(&code.to_le_bytes());
    Some(STUN_RESULT_LEN)
}

/// Read a result record back. `None` unless it is exactly one record.
#[must_use]
pub fn parse_stun_result(buf: &[u8]) -> Option<(u8, [u8; 4], u16, u16)> {
    if buf.len() != STUN_RESULT_LEN {
        return None;
    }
    let ip = [buf[1], buf[2], buf[3], buf[4]];
    Some((
        buf[0],
        ip,
        u16::from_le_bytes([buf[5], buf[6]]),
        u16::from_le_bytes([buf[7], buf[8]]),
    ))
}
