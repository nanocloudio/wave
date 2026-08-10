// Bounded, no_std, no-alloc SIP dialog transaction machine — the UAC/UAS state
// transitions for a two-party PCMU call. `include!`d by the host crate (tests)
// and the SIP `.fmod`. It decides *what* a compliant endpoint does next; the
// composing module supplies the clock, the sockets, the message bytes (via
// `sip_core`), and the media wiring.
//
// This is the "session transaction" layer: given the current dialog state and
// one event (a local call/hangup, a received request or response, or a
// retransmit-timer expiry), it yields the next state plus at most one message
// to send and one media command. It emits only protocol facts — it never
// formats bytes, touches a socket, reads a clock, or decides call *policy*
// (whether to answer is the caller's `answer` input, kept out of the machine).
//
// The single implementation of the `SipPhase` dialog transitions.
// under Conclave plan S4.3 (T4.3.4). Transitions are behaviour-exact with those
// handlers; the coverage lives in `modules/foundation/sip/tests/sip_dialog_vectors.rs`.

/// Maximum retransmissions before a transaction gives up and returns to idle
/// (origin `MAX_RETRANSMIT`). The exponential backoff schedule that paces them
/// is the caller's; this machine only counts attempts.
pub const SIP_MAX_RETRANSMIT: u8 = 7;

/// Dialog state. `Init`/`BindWait` transport setup is the module's concern and
/// deliberately absent — this machine starts at [`SipState::Ready`].
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SipState {
    /// Idle: may place a call or answer an incoming `INVITE`.
    Ready,
    /// UAC sent `INVITE`, awaiting a final response.
    Inviting,
    /// UAS sent `200 OK`, awaiting the `ACK`.
    WaitAck,
    /// Media flowing.
    Active,
    /// UAC sent `BYE`, awaiting its `200 OK`.
    ByeSent,
}

/// An input to the machine. Received messages are pre-classified by the caller
/// (method line for requests, status code for responses — see `sip_core`).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SipEvent {
    /// Local user places a call (from `Ready`).
    LocalInvite,
    /// Local user hangs up (from `Active`).
    LocalBye,
    /// Incoming `INVITE`. `answer` is the caller's accept policy: `true`
    /// auto-answers (origin `auto_answer`), `false` ignores the request.
    RxInvite { answer: bool },
    /// Incoming `ACK`.
    RxAck,
    /// Incoming `BYE`.
    RxBye,
    /// Incoming response carrying this status code.
    RxResponse { code: u16 },
    /// The retransmit timer expired (the caller decides when).
    Timeout,
}

/// A SIP message the caller should format (via `sip_core`) and send. `Retransmit`
/// means resend the last transmitted message unchanged.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SipSend {
    Invite,
    /// `200 OK` answering an `INVITE`.
    Ok,
    Ack,
    Bye,
    /// `200 OK` answering a `BYE`.
    ByeOk,
    /// Resend the last transmitted message.
    Retransmit,
}

/// A media-path command accompanying a transition.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum MediaCmd {
    None,
    /// Begin the jitter buffer / RTP flow against the negotiated endpoint.
    Start,
    /// Tear the media flow down.
    Stop,
}

/// The effects of one event: at most one message to send and one media command,
/// plus whether the caller should restart its retransmit clock.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct SipStep {
    /// Message to transmit, if any.
    pub send: Option<SipSend>,
    /// Media-path command.
    pub media: MediaCmd,
    /// Restart the retransmit timer (transaction (re)armed).
    pub reset_timer: bool,
}

impl SipStep {
    const NONE: Self = Self {
        send: None,
        media: MediaCmd::None,
        reset_timer: false,
    };

    const fn send(msg: SipSend) -> Self {
        Self {
            send: Some(msg),
            media: MediaCmd::None,
            reset_timer: true,
        }
    }
}

/// The dialog transaction machine. Holds the state and the retransmit attempt
/// counter; all timing is external.
pub struct SipDialogFsm {
    state: SipState,
    retransmit_count: u8,
}

impl Default for SipDialogFsm {
    fn default() -> Self {
        Self::new()
    }
}

impl SipDialogFsm {
    /// A fresh machine in [`SipState::Ready`].
    #[must_use]
    pub const fn new() -> Self {
        Self {
            state: SipState::Ready,
            retransmit_count: 0,
        }
    }

    /// The current dialog state.
    #[must_use]
    pub fn state(&self) -> SipState {
        self.state
    }

    /// Advance a retransmitting state on timer expiry: resend until the attempt
    /// limit, then give up to `Ready`.
    fn on_timeout(&mut self) -> SipStep {
        if self.retransmit_count >= SIP_MAX_RETRANSMIT {
            self.state = SipState::Ready;
            SipStep::NONE
        } else {
            self.retransmit_count += 1;
            SipStep {
                send: Some(SipSend::Retransmit),
                media: MediaCmd::None,
                reset_timer: true,
            }
        }
    }

    /// Feed one event; returns the effects the caller must apply.
    pub fn on_event(&mut self, ev: SipEvent) -> SipStep {
        match (self.state, ev) {
            // --- Ready -----------------------------------------------------
            (SipState::Ready, SipEvent::LocalInvite) => {
                self.retransmit_count = 0;
                self.state = SipState::Inviting;
                SipStep::send(SipSend::Invite)
            }
            (SipState::Ready, SipEvent::RxInvite { answer: true }) => {
                self.retransmit_count = 0;
                self.state = SipState::WaitAck;
                SipStep {
                    send: Some(SipSend::Ok),
                    media: MediaCmd::Start,
                    reset_timer: true,
                }
            }
            // Not answering: ignore the request, stay ready.
            (SipState::Ready, SipEvent::RxInvite { answer: false }) => SipStep::NONE,

            // --- Inviting (UAC awaiting final response) --------------------
            (SipState::Inviting, SipEvent::RxResponse { code }) if (100..200).contains(&code) => {
                // Provisional: reset the transaction timer, keep waiting.
                self.retransmit_count = 0;
                SipStep {
                    send: None,
                    media: MediaCmd::None,
                    reset_timer: true,
                }
            }
            (SipState::Inviting, SipEvent::RxResponse { code }) if (200..300).contains(&code) => {
                // Success answered/unanswered by the caller's SDP check: on a
                // usable answer, ACK + start media + go active; otherwise ACK
                // and fall back to ready. The caller signals which by choosing
                // the follow-up — here we take the media-usable path and the
                // caller elects `RxResponse{code:0}`-style rejection via the
                // dedicated helper below when SDP is unusable.
                self.state = SipState::Active;
                SipStep {
                    send: Some(SipSend::Ack),
                    media: MediaCmd::Start,
                    reset_timer: false,
                }
            }
            (SipState::Inviting, SipEvent::RxResponse { code }) if code >= 300 => {
                // Rejected: ACK the final response, return to ready.
                self.state = SipState::Ready;
                SipStep {
                    send: Some(SipSend::Ack),
                    media: MediaCmd::None,
                    reset_timer: false,
                }
            }
            (SipState::Inviting, SipEvent::Timeout) => self.on_timeout(),

            // --- WaitAck (UAS awaiting ACK) -------------------------------
            (SipState::WaitAck, SipEvent::RxAck) => {
                self.state = SipState::Active;
                SipStep::NONE
            }
            // Retransmitted INVITE: resend the 200 OK.
            (SipState::WaitAck, SipEvent::RxInvite { .. }) => SipStep {
                send: Some(SipSend::Retransmit),
                media: MediaCmd::None,
                reset_timer: false,
            },
            (SipState::WaitAck, SipEvent::Timeout) => self.on_timeout(),

            // --- Active ---------------------------------------------------
            (SipState::Active, SipEvent::LocalBye) => {
                self.retransmit_count = 0;
                self.state = SipState::ByeSent;
                SipStep {
                    send: Some(SipSend::Bye),
                    media: MediaCmd::Stop,
                    reset_timer: true,
                }
            }
            (SipState::Active, SipEvent::RxBye) => {
                self.state = SipState::Ready;
                SipStep {
                    send: Some(SipSend::ByeOk),
                    media: MediaCmd::Stop,
                    reset_timer: false,
                }
            }

            // --- ByeSent (UAC awaiting BYE 200) ---------------------------
            (SipState::ByeSent, SipEvent::RxResponse { code }) if code >= 200 => {
                self.state = SipState::Ready;
                SipStep::NONE
            }
            (SipState::ByeSent, SipEvent::Timeout) => self.on_timeout(),

            // No transition for this (state, event).
            _ => SipStep::NONE,
        }
    }

    /// The UAC received a `2xx` whose SDP answer is unusable: ACK it but do not
    /// start media, returning to `Ready` (origin `sip_handle_incoming_inviting`
    /// bad-SDP branch). Kept explicit so the media-usable path stays the default
    /// `RxResponse` transition.
    pub fn on_invite_ok_unusable_sdp(&mut self) -> SipStep {
        if self.state == SipState::Inviting {
            self.state = SipState::Ready;
            SipStep {
                send: Some(SipSend::Ack),
                media: MediaCmd::None,
                reset_timer: false,
            }
        } else {
            SipStep::NONE
        }
    }
}
