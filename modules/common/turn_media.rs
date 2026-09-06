// TURN media-plane framing for RTP/RTCP adapters.
// The adapter is allocation-free: callers provide the packet scratch and the
// relay socket remains owned by the network module. It accepts both TURN
// Send/Data Indications and ChannelData, so a deployment may switch relay
// framing without changing its codec or jitter pipeline.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TurnMedia<'a> {
    Channel { channel: u16, payload: &'a [u8] },
    Indication { payload: &'a [u8] },
    Invalid,
}

pub fn write_send(
    txn: &[u8; STUN_TXN_LEN],
    peer_addr: [u8; 4],
    peer_port: u16,
    media: &[u8],
    out: &mut [u8],
) -> Option<usize> {
    write_send_indication(txn, peer_addr, peer_port, media, out)
}

pub fn parse<'a>(packet: &'a [u8]) -> TurnMedia<'a> {
    match classify_relayed(packet) {
        RelayedDatagram::Channel {
            channel,
            offset,
            len,
        } => TurnMedia::Channel {
            channel,
            payload: &packet[offset..offset + len],
        },
        RelayedDatagram::Stun => {
            let Some(header) = parse_stun_header(packet) else {
                return TurnMedia::Invalid;
            };
            if header.class != STUN_CLASS_INDICATION
                || (header.method != TURN_METHOD_DATA && header.method != TURN_METHOD_SEND)
            {
                return TurnMedia::Invalid;
            }
            let Some((at, len)) = find_attribute(packet, &header, ATTR_DATA) else {
                return TurnMedia::Invalid;
            };
            TurnMedia::Indication {
                payload: &packet[at..at + len],
            }
        }
        RelayedDatagram::Unrecognised => TurnMedia::Invalid,
    }
}
