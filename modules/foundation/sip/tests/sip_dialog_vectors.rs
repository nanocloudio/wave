//! SIP dialog transaction FSM vectors (Conclave plan S4.3, T4.3.4).
//!
//! Lock `modules/common/sip_dialog.rs` to the `SipPhase` handler transitions of the
//! dialog surface: outgoing/incoming call setup, hangup
//! from either side, rejection, and the bounded retransmit/give-up behaviour.

use super::sip::sip_dialog::{
    MediaCmd, SipDialogFsm, SipEvent, SipSend, SipState, SIP_MAX_RETRANSMIT,
};

#[test]
fn outgoing_call_happy_path() {
    let mut fsm = SipDialogFsm::new();

    let step = fsm.on_event(SipEvent::LocalInvite);
    assert_eq!(step.send, Some(SipSend::Invite));
    assert_eq!(fsm.state(), SipState::Inviting);

    // Provisional response keeps us inviting but re-arms the timer.
    let step = fsm.on_event(SipEvent::RxResponse { code: 180 });
    assert_eq!(step.send, None);
    assert!(step.reset_timer);
    assert_eq!(fsm.state(), SipState::Inviting);

    // 200 OK with a usable answer: ACK, start media, active.
    let step = fsm.on_event(SipEvent::RxResponse { code: 200 });
    assert_eq!(step.send, Some(SipSend::Ack));
    assert_eq!(step.media, MediaCmd::Start);
    assert_eq!(fsm.state(), SipState::Active);
}

#[test]
fn outgoing_call_rejected() {
    let mut fsm = SipDialogFsm::new();
    fsm.on_event(SipEvent::LocalInvite);
    let step = fsm.on_event(SipEvent::RxResponse { code: 486 });
    assert_eq!(step.send, Some(SipSend::Ack), "reject is still ACKed");
    assert_eq!(step.media, MediaCmd::None);
    assert_eq!(fsm.state(), SipState::Ready);
}

#[test]
fn outgoing_call_ok_with_unusable_sdp() {
    let mut fsm = SipDialogFsm::new();
    fsm.on_event(SipEvent::LocalInvite);
    let step = fsm.on_invite_ok_unusable_sdp();
    assert_eq!(step.send, Some(SipSend::Ack));
    assert_eq!(step.media, MediaCmd::None, "no media on unusable answer");
    assert_eq!(fsm.state(), SipState::Ready);
}

#[test]
fn incoming_call_answered() {
    let mut fsm = SipDialogFsm::new();

    let step = fsm.on_event(SipEvent::RxInvite { answer: true });
    assert_eq!(step.send, Some(SipSend::Ok));
    assert_eq!(step.media, MediaCmd::Start);
    assert_eq!(fsm.state(), SipState::WaitAck);

    let step = fsm.on_event(SipEvent::RxAck);
    assert_eq!(step.send, None);
    assert_eq!(fsm.state(), SipState::Active);
}

#[test]
fn incoming_call_ignored_when_not_answering() {
    let mut fsm = SipDialogFsm::new();
    let step = fsm.on_event(SipEvent::RxInvite { answer: false });
    assert_eq!(step.send, None);
    assert_eq!(fsm.state(), SipState::Ready);
}

#[test]
fn waitack_retransmits_ok_on_duplicate_invite() {
    let mut fsm = SipDialogFsm::new();
    fsm.on_event(SipEvent::RxInvite { answer: true });
    let step = fsm.on_event(SipEvent::RxInvite { answer: true });
    assert_eq!(step.send, Some(SipSend::Retransmit));
    assert_eq!(fsm.state(), SipState::WaitAck);
}

#[test]
fn local_hangup_sends_bye_then_confirms() {
    let mut fsm = SipDialogFsm::new();
    fsm.on_event(SipEvent::RxInvite { answer: true });
    fsm.on_event(SipEvent::RxAck);
    assert_eq!(fsm.state(), SipState::Active);

    let step = fsm.on_event(SipEvent::LocalBye);
    assert_eq!(step.send, Some(SipSend::Bye));
    assert_eq!(step.media, MediaCmd::Stop);
    assert_eq!(fsm.state(), SipState::ByeSent);

    let step = fsm.on_event(SipEvent::RxResponse { code: 200 });
    assert_eq!(step.send, None);
    assert_eq!(fsm.state(), SipState::Ready);
}

#[test]
fn remote_hangup_answers_bye() {
    let mut fsm = SipDialogFsm::new();
    fsm.on_event(SipEvent::LocalInvite);
    fsm.on_event(SipEvent::RxResponse { code: 200 });
    assert_eq!(fsm.state(), SipState::Active);

    let step = fsm.on_event(SipEvent::RxBye);
    assert_eq!(step.send, Some(SipSend::ByeOk));
    assert_eq!(step.media, MediaCmd::Stop);
    assert_eq!(fsm.state(), SipState::Ready);
}

#[test]
fn invite_retransmits_then_gives_up() {
    let mut fsm = SipDialogFsm::new();
    fsm.on_event(SipEvent::LocalInvite);

    // Up to the limit, each timeout resends.
    for _ in 0..SIP_MAX_RETRANSMIT {
        let step = fsm.on_event(SipEvent::Timeout);
        assert_eq!(step.send, Some(SipSend::Retransmit));
        assert_eq!(fsm.state(), SipState::Inviting);
    }
    // One past the limit gives up to Ready with nothing to send.
    let step = fsm.on_event(SipEvent::Timeout);
    assert_eq!(step.send, None);
    assert_eq!(fsm.state(), SipState::Ready);
}

/// The retransmit budget is per transaction: a fresh INVITE after an abandoned
/// one gets the full allowance, not a carried-over count.
#[test]
fn retransmit_budget_resets_per_transaction() {
    let mut fsm = SipDialogFsm::default();
    fsm.on_event(SipEvent::LocalInvite);
    for _ in 0..=SIP_MAX_RETRANSMIT {
        fsm.on_event(SipEvent::Timeout);
    }
    assert_eq!(fsm.state(), SipState::Ready);

    fsm.on_event(SipEvent::LocalInvite);
    for attempt in 1..=SIP_MAX_RETRANSMIT {
        assert_eq!(
            fsm.on_event(SipEvent::Timeout).send,
            Some(SipSend::Retransmit),
            "second dialog lost its budget at attempt {attempt}"
        );
    }
}

/// Events that make no sense for the current state are inert — no message, no
/// media command, no state change.
#[test]
fn out_of_state_events_are_inert() {
    let mut fsm = SipDialogFsm::default();
    assert_eq!(fsm.on_event(SipEvent::LocalBye).send, None);
    assert_eq!(fsm.state(), SipState::Ready);

    let mut fsm = SipDialogFsm::default();
    assert_eq!(fsm.on_event(SipEvent::RxAck).send, None);
    assert_eq!(fsm.state(), SipState::Ready);

    let mut fsm = SipDialogFsm::default();
    fsm.on_event(SipEvent::LocalInvite);
    assert_eq!(
        fsm.on_event(SipEvent::LocalInvite).send,
        None,
        "duplicate INVITE must not re-send"
    );
    assert_eq!(fsm.state(), SipState::Inviting);
}
