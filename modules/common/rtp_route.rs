//! Bounded negotiated RTP route table keyed by MID, payload type and SSRC.

pub const RTP_ROUTE_MAX: usize = 16;
pub const RTP_MID_MAX: usize = 32;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RtpRoute {
    pub mid: [u8; RTP_MID_MAX],
    pub mid_len: u8,
    pub payload_type: u8,
    pub ssrc: u32,
    pub codec_index: u8,
}

#[derive(Clone, Copy)]
pub struct RtpRouteTable {
    routes: [Option<RtpRoute>; RTP_ROUTE_MAX],
    len: usize,
}

impl Default for RtpRouteTable {
    fn default() -> Self {
        Self::new()
    }
}

impl RtpRouteTable {
    pub const fn new() -> Self {
        Self {
            routes: [None; RTP_ROUTE_MAX],
            len: 0,
        }
    }

    pub fn add(&mut self, route: RtpRoute) -> bool {
        if route.mid_len as usize > RTP_MID_MAX {
            return false;
        }
        if self.routes.iter().flatten().any(|r| {
            r.payload_type == route.payload_type
                && r.ssrc == route.ssrc
                && r.mid_len == route.mid_len
                && r.mid[..r.mid_len as usize] == route.mid[..route.mid_len as usize]
        }) {
            return false;
        }
        if self.len == RTP_ROUTE_MAX {
            return false;
        }
        self.routes[self.len] = Some(route);
        self.len += 1;
        true
    }

    /// Install a negotiated binding, replacing the previous generation for
    /// the same MID/PT/SSRC tuple. Reoffers therefore cannot exhaust the
    /// bounded table or leave stale codec routing behind.
    pub fn upsert(&mut self, route: RtpRoute) -> bool {
        if route.mid_len as usize > RTP_MID_MAX {
            return false;
        }
        if let Some(slot) = self.routes.iter_mut().flatten().find(|r| {
            r.payload_type == route.payload_type
                && r.ssrc == route.ssrc
                && r.mid_len == route.mid_len
                && r.mid[..r.mid_len as usize] == route.mid[..route.mid_len as usize]
        }) {
            *slot = route;
            return true;
        }
        self.add(route)
    }

    pub fn resolve(&self, mid: &[u8], payload_type: u8, ssrc: u32) -> Option<RtpRoute> {
        let mut best = None;
        let mut score = 0u8;
        for route in self.routes.iter().flatten() {
            if route.payload_type != payload_type
                || (route.ssrc != 0 && route.ssrc != ssrc)
                || (route.mid_len != 0 && &route.mid[..route.mid_len as usize] != mid)
            {
                continue;
            }
            let specificity = u8::from(route.ssrc != 0) + u8::from(route.mid_len != 0);
            if specificity >= score {
                score = specificity;
                best = Some(*route);
            }
        }
        best
    }

    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }
}
