//! Bounded encoded-media packetization boundary for the production RTP graph.
//!
//! Spectra supplies encoded access units through `rtp_media_wire`; this core
//! turns them into RTP payload plans without allocation. The transport owns
//! encryption and pacing, while this type owns codec framing.

use super::rtp_h264::{H264FuA, H264Packet};
use super::rtp_media_wire::{EncodedFrame, CODEC_H264, CODEC_VP8};
use super::rtp_vp8::{Vp8Packet, Vp8Packetizer};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MediaPacket {
    pub seq: u16,
    pub timestamp: u32,
    pub ssrc: u32,
    pub marker: bool,
    pub len: usize,
}

pub enum EncodedPacketizer<'a> {
    H264(H264FuA<'a>),
    Vp8(Vp8Packetizer<'a>),
}

impl<'a> EncodedPacketizer<'a> {
    pub fn new(frame: EncodedFrame<'a>, mtu_payload: usize, seq: u16, ssrc: u32) -> Option<Self> {
        match frame.codec {
            CODEC_H264 => Some(Self::H264(H264FuA::new(
                frame.payload,
                mtu_payload,
                seq,
                frame.timestamp,
                ssrc,
            )?)),
            CODEC_VP8 => Some(Self::Vp8(Vp8Packetizer::new(
                frame.payload,
                mtu_payload,
                seq,
                frame.timestamp,
                ssrc,
            )?)),
            _ => None,
        }
    }

    pub fn next(&mut self, out: &mut [u8]) -> Option<MediaPacket> {
        match self {
            Self::H264(p) => p.next(out).map(|x: H264Packet| MediaPacket {
                seq: x.seq,
                timestamp: x.timestamp,
                ssrc: x.ssrc,
                marker: x.marker,
                len: x.len,
            }),
            Self::Vp8(p) => p.next(out).map(|x: Vp8Packet| MediaPacket {
                seq: x.seq,
                timestamp: x.timestamp,
                ssrc: x.ssrc,
                marker: x.marker,
                len: x.len,
            }),
        }
    }
}
