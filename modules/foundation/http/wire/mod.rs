//! Wire codecs — pure byte-level parse and build, one file per generation.
//!
//! Everything here is I/O-free: no syscalls, no channels, no clock, no state
//! beyond what a caller passes in. That is what makes the whole tier testable
//! without a socket, and it is why the RFC vectors live against these files
//! rather than against the server or client that drives them.
//!
//! Role-neutral by construction. `h1` serves the server's request parser and
//! the client's response parser; `ws` serves the server's frame path and the
//! client's masked writer. A codec that needed to know which side it was on
//! would belong one directory up.
//!
//! Feature-gated per generation (RFC module_variants), so `http-web.fmod` links
//! neither `h2`/`hpack` nor `h3`/`qpack`. Each is `pub` only under `host-test`,
//! keeping the firmware's symbol surface unchanged while letting the vectors
//! reach it — `modules/**` has a hard inline-test ban.

// RFC 7541 Appendix B Huffman table + decoder. Gated on h2 OR h3, NOT h2
// alone: RFC 9204 §4.1.2 has QPACK reuse this exact table, so an h3-without-h2
// variant still needs it. Living inside `hpack` made h3 depend on h2, which
// defeats the point of the variant split.
#[cfg(any(feature = "h2", feature = "h3"))]
pub(crate) mod huffman {
    include!("../../../common/huffman_core.rs");
}

// Method vocabulary — shared by h1, h2 and h3, so it is NOT feature-gated per
// generation. `h1` is always compiled, and every variant that adds a generation
// adds another consumer of the same table.
#[cfg(not(feature = "host-test"))]
pub(crate) mod method;
#[cfg(feature = "host-test")]
pub mod method;

#[cfg(not(feature = "host-test"))]
pub(crate) mod h1;
#[cfg(feature = "host-test")]
pub mod h1;

#[cfg(all(feature = "h2", not(feature = "host-test")))]
pub(crate) mod h2;
#[cfg(all(feature = "h2", feature = "host-test"))]
pub mod h2;

#[cfg(all(feature = "h3", not(feature = "host-test")))]
pub(crate) mod h3;
#[cfg(all(feature = "h3", feature = "host-test"))]
pub mod h3;

#[cfg(not(feature = "host-test"))]
pub(crate) mod ws;
#[cfg(feature = "host-test")]
pub mod ws;

#[cfg(all(feature = "h2", not(feature = "host-test")))]
pub(crate) mod hpack;
#[cfg(all(feature = "h2", feature = "host-test"))]
pub mod hpack;

#[cfg(all(feature = "h3", not(feature = "host-test")))]
pub(crate) mod qpack;
#[cfg(all(feature = "h3", feature = "host-test"))]
pub mod qpack;
