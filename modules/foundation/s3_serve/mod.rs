//! `s3_serve` — an S3 server behind `http`'s application routes, storing
//! through any `storage.object` provider.
//!
//! The module is an exchange provider: it answers the request records `http`
//! hands it on `request_in` and writes its answers to `response_out`. It never holds a body whole: a
//! request body moves to the provider record by record through the streamed
//! put, as the module grants credit for it; an object moves to the peer record
//! by record through ranged reads, as `http` grants credit back.
//!
//! **Authority is the provider's.** Each access key in the credentials file
//! is bound to a mesh capability over a scope (`bucket/`); the module verifies
//! every chain when it loads the file and presents it to the provider once,
//! and every operation for that key runs under the grant the provider
//! answered. The module keeps no access list: whether a key may touch a
//! bucket is the provider's answer to the operation, under the grant.
//!
//! The protocol decisions — operations, naming, errors, XML, ranges,
//! `aws-chunked`, the credentials file, listings, the part list — are the
//! pure `s3_serve_core.rs`; signatures are `sigv4_core.rs`. This file is the
//! state each exchange moves through and the provider calls that move it.

#![cfg_attr(not(feature = "host-test"), no_std)]
#![deny(clippy::unwrap_used)]
#![allow(
    dead_code,
    unused_imports,
    reason = "the SDK is path-mounted into every module, so each compile sees \
              the whole ABI surface while using a subset"
)]
#![allow(
    clippy::not_unsafe_ptr_arg_deref,
    reason = "the module ABI entry points take raw state and syscall pointers \
              whose validity is the runtime's half of the contract, and the \
              signature is fixed by that contract rather than chosen here"
)]

use core::ffi::c_void;

#[path = "../../../target/fluxor/fluxor-abi/sdk/abi.rs"]
mod abi;
use abi::SyscallTable;

include!("../../../target/fluxor/fluxor-abi/sdk/runtime.rs");
include!("../../../target/fluxor/fluxor-abi/sdk/runtime/params.rs");

// SHA-256 for signatures, SHA-512 and the field helpers Ed25519 needs, and
// Ed25519 for capability chains: all SDK-owned.
include!("../../../target/fluxor/fluxor-abi/sdk/crypto/sha256.rs");
include!("../../../target/fluxor/fluxor-abi/sdk/crypto/sha384.rs");
include!("../../../target/fluxor/fluxor-abi/sdk/crypto/hmac.rs");
include!("../../../target/fluxor/fluxor-abi/sdk/crypto/p256.rs");
include!("../../../target/fluxor/fluxor-abi/sdk/crypto/ed25519.rs");
include!("../../common/sigv4_core.rs");
include!("../../common/s3_serve_core.rs");

// The exchange records this module answers, as a provider.
use abi::contracts::exchange::{
    self as exchange, abort, flag, parse_request, write_body, write_credit, write_response_head,
    ExchangeId, Record, RequestHead, ResponseHead, BODY_MAX, RECORD_MAX,
};

use abi::contracts::mesh::capability as cap;
use abi::contracts::storage::handle::STORAGE_KEY_MAX;
use abi::contracts::storage::object as obj;
use abi::fence::{Fence, WIRE_MAX_LEN};
use abi::kernel_abi::errno;

// ── Ceilings ──────────────────────────────────────────────────────────────

/// Access keys the credentials file may hold. Each is a grant the provider
/// keeps for the life of the module, so this is bounded below the provider's
/// own grant table.
pub const MAX_CREDENTIALS: usize = 16;
/// Exchanges served at once. One past it is answered `503 SlowDown` at once.
pub const MAX_EXCHANGES: usize = 32;
/// Multipart uploads open at once. One past it is answered `503 SlowDown`.
pub const MAX_UPLOADS: usize = 64;
/// Multipart completions in progress at once, each holding every listed
/// part's number and entity tag. One past it is answered `503 SlowDown`.
pub const MAX_COMPLETIONS: usize = 4;
/// Longest entity tag a provider may answer, in bytes. A longer one is
/// answered `InternalError` rather than cut, since a cut tag names nothing.
pub const ETAG_MAX: usize = 32;
/// Largest credentials file, in bytes.
pub const CREDS_FILE_MAX: usize = 16 * 1024;
/// Request-body credit an exchange holds out to `http` at once: what may be
/// in flight between the client and the provider for one upload.
pub const BODY_WINDOW: u32 = 64 * 1024;
/// One `LIST` page buffer.
pub const LIST_PAGE_BUF: usize = 32 * 1024;
/// Bytes of a listing document kept for its head and tail: the XML
/// declaration and `<ListBucketResult>` opening with an escaped prefix
/// (under 1.9 KiB), and the close with a continuation token or an escaped
/// `NextMarker` (under 1.6 KiB).
const LIST_DOC_RESERVE: usize = 4096;
/// The most one listed entry's XML can be per byte it takes in a `LIST`
/// page. An entry of key `K` (its object name, at least four bytes longer
/// than the key `k` it renders) and etag `T` takes `19 + K + T` page bytes
/// and renders at most `180 + 6k + 2T` (a key escaped as `&quot;` runs),
/// which is within 8 times its page bytes for every entry a page can hold.
const LIST_EXPANSION: usize = 8;
/// The `LIST` page a listing asks for: whatever the provider fills it with,
/// the entries render into the document beside its head and tail.
const LIST_RENDER_CAP: usize = (LIST_PAGE_BUF - LIST_DOC_RESERVE) / LIST_EXPANSION;
const _: () = assert!(
    LIST_RENDER_CAP >= obj::list::min_out_cap(NAME_MAX, u8::MAX as usize),
    "a render-capped page still holds the longest entry"
);
/// The highest object-size ceiling a deployment may set, in MiB: S3's own
/// 5 TiB.
pub const OBJECT_CEILING_MIB: u32 = 5 * 1024 * 1024;
/// The largest part, S3's own 5 GiB.
pub const PART_SIZE_MAX: u64 = 5 << 30;
/// How long an upload may sit untouched before its staging is reclaimed.
pub const UPLOAD_TTL_S: u64 = 24 * 3600;
/// Whitespace keeps a long `CompleteMultipartUpload` response alive at this
/// interval, as S3 does, so neither `http` nor the client times it out.
const KEEPALIVE_MS: u64 = 5000;
/// Longest object or staging name.
const NAME_MAX: usize = STORAGE_KEY_MAX;
/// Longest `Content-Type` an object may be stored with; longer is `InvalidArgument`.
const CT_MAX: usize = 128;

// ── State ─────────────────────────────────────────────────────────────────

#[derive(Clone, Copy)]
struct Cred {
    access_key: [u8; S3_ACCESS_KEY_MAX],
    ak_len: u8,
    secret: [u8; S3_SECRET_MAX],
    secret_len: u8,
    scope: [u8; NAME_MAX],
    scope_len: u8,
    chain: [u8; cap::MAX_CHAIN_BYTES],
    chain_len: u16,
    /// Decoded mTLS peer fingerprint this key is bound to; empty when unbound.
    peer: [u8; S3_PEER_MAX / 2],
    peer_len: u8,
    /// The provider's grant for this key; `-1` until presented.
    grant: i32,
}

const CRED_EMPTY: Cred = Cred {
    access_key: [0; S3_ACCESS_KEY_MAX],
    ak_len: 0,
    secret: [0; S3_SECRET_MAX],
    secret_len: 0,
    scope: [0; NAME_MAX],
    scope_len: 0,
    chain: [0; cap::MAX_CHAIN_BYTES],
    chain_len: 0,
    peer: [0; S3_PEER_MAX / 2],
    peer_len: 0,
    grant: -1,
};

impl Cred {
    fn ak(&self) -> &[u8] {
        &self.access_key[..self.ak_len as usize]
    }
    fn scope(&self) -> &[u8] {
        &self.scope[..self.scope_len as usize]
    }
    fn bucket(&self) -> &[u8] {
        s3_scope_bucket(self.scope()).unwrap_or(&[])
    }
}

/// How a request's body is checked.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Payload {
    /// The body's SHA-256 is signed; compared once the body ends.
    Hashed([u8; 32]),
    /// Not signed.
    Unsigned,
    /// `aws-chunked`, each chunk signed.
    Chunked,
}

/// Where an exchange stands.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Phase {
    Free,
    /// A whole response is staged in `out`; the exchange ends once it is
    /// written.
    Answer,
    /// Body records go to the provider's streamed put.
    PutBody,
    /// The streamed put is committing (asked again while pending).
    PutCommit,
    /// Reading the committed object's metadata for its ETag.
    PutHead,
    /// Reading an object's metadata and judging the request's conditions
    /// and range against it (asked again while the provider is not ready).
    ReadHead,
    /// Opening the object for ranged reads (asked again likewise).
    ReadOpen,
    /// Streaming an object to the peer.
    GetBody,
    /// Paging through a listing.
    List,
    /// Recording a new upload's marker.
    UploadCreate,
    /// Reading the completion body's part list.
    CompleteParts,
    /// Checking each listed part against its staging.
    CompleteCheck,
    /// Copying parts into the final object.
    CompleteCopy,
    /// Committing the completed object.
    CompleteCommit,
    /// The object is committed; its result document waits for credit.
    CompleteResult,
    /// Removing an upload's staging.
    UploadDelete,
    /// Deleting one object (asked again while pending).
    Delete,
    /// Probing a bucket under the key's grant (HEAD/PUT/location).
    BucketProbe,
}

/// Which records an exchange's response is composing.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Out {
    /// Nothing owed.
    Idle,
    /// A record staged in `out` awaiting `response_out`.
    Pending,
}

struct Exchange {
    phase: Phase,
    id: ExchangeId,
    op: S3Op,
    method: u8,
    cred: u8,
    /// Request-body records still expected.
    body_open: bool,
    /// Request-body credit granted and not yet consumed, and credit owed
    /// back to grant.
    credit_out: u32,
    credit_owed: u32,
    /// Response-body credit `http` has granted.
    resp_credit: u32,
    /// The response HEAD has gone.
    head_sent: bool,
    /// `x-amz-request-id`.
    request_id: [u8; 16],
    /// Object or staging name the exchange addresses.
    name: [u8; NAME_MAX],
    name_len: usize,
    /// Byte count of the bucket at the front of `name`.
    bucket_len: usize,
    /// Upload id, for multipart operations.
    upload: [u8; S3_UPLOAD_ID_LEN],
    upload_slot: i16,
    part: u32,
    // Request body.
    payload: Payload,
    hasher: Option<Sha256>,
    chunked: Option<S3Chunked>,
    seed: [u8; 64],
    signing_key: [u8; 32],
    amz_date: [u8; 16],
    scope_date: [u8; 8],
    declared: u64,
    received: u64,
    // Provider handles and buffers whose addresses a pending call names.
    handle: i32,
    fence: [u8; WIRE_MAX_LEN],
    arg: [u8; 2 * NAME_MAX + 64],
    arg_len: usize,
    // Object reads.
    offset: u64,
    end: u64,
    etag: [u8; ETAG_MAX],
    etag_len: usize,
    size: u64,
    mtime: u64,
    // Listing.
    list: ListState,
    // Completion.
    parts: *mut u32,
    /// Each listed part's entity tag: a length byte, then `ETAG_MAX` bytes.
    part_etags: *mut u8,
    parts_len: u32,
    part_at: u32,
    parts_reader: Option<S3PartsReader>,
    parts_bad: Option<S3Err>,
    keepalive_ms: u64,
    // The staged record.
    out_state: Out,
    out: *mut u8,
    out_len: usize,
    /// The response ends with the staged record.
    out_final: bool,
}

#[derive(Clone, Copy)]
struct ListState {
    v2: bool,
    url: bool,
    max: u16,
    emitted: u16,
    prefix: [u8; NAME_MAX],
    prefix_len: u16,
    delim: [u8; 8],
    delim_len: u8,
    cursor: [u8; NAME_MAX],
    cursor_len: u16,
    last_cp: [u8; NAME_MAX],
    last_cp_len: u16,
    /// Keys at or before this are skipped (`marker` / `start-after`).
    after: [u8; NAME_MAX],
    after_len: u16,
    /// The listing reached its end.
    done: bool,
    /// The response document has been opened.
    opened: bool,
    page: *mut u8,
    /// The document bytes rendered and not yet sent, in `page`'s tail.
    pending: u16,
}

const LIST_EMPTY: ListState = ListState {
    v2: false,
    url: false,
    max: 0,
    emitted: 0,
    prefix: [0; NAME_MAX],
    prefix_len: 0,
    delim: [0; 8],
    delim_len: 0,
    cursor: [0; NAME_MAX],
    cursor_len: 0,
    last_cp: [0; NAME_MAX],
    last_cp_len: 0,
    after: [0; NAME_MAX],
    after_len: 0,
    done: false,
    opened: false,
    page: core::ptr::null_mut(),
    pending: 0,
};

#[derive(Clone, Copy)]
struct Upload {
    used: bool,
    id: [u8; S3_UPLOAD_ID_LEN],
    /// The object name the upload completes.
    name: [u8; NAME_MAX],
    name_len: u16,
    bucket_len: u8,
    cred: u8,
    touched: u64,
    /// An exchange is completing or aborting it.
    busy: bool,
}

const UPLOAD_EMPTY: Upload = Upload {
    used: false,
    id: [0; S3_UPLOAD_ID_LEN],
    name: [0; NAME_MAX],
    name_len: 0,
    bucket_len: 0,
    cred: 0,
    touched: 0,
    busy: false,
};

/// Where the module is in coming up.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Boot {
    /// Reading the credentials file.
    Load,
    /// Verifying chains (waits for a trusted clock).
    Verify,
    /// Presenting each chain to the provider.
    Present,
    /// Removing staging left by uploads that did not survive a restart.
    Reclaim,
    /// Asking the provider whether it can take a streamed write at all.
    Probe,
    Serving,
    /// Refused to serve; every request is answered 503.
    Failed,
}

#[repr(C)]
struct State {
    syscalls: *const SyscallTable,
    request_in: i32,
    response_out: i32,
    boot: Boot,
    // Params.
    creds_path: [u8; 256],
    creds_path_len: usize,
    /// The `credentials` path was longer than the 256 bytes held for it. A
    /// truncated path names a different file, so construction refuses it
    /// rather than reading whatever is there.
    creds_path_bad: bool,
    region: [u8; 32],
    region_len: usize,
    roots: [[u8; 32]; cap::MAX_ROOTS],
    roots_len: usize,
    roots_bad: bool,
    object_bad: bool,
    region_bad: bool,
    max_object: u64,
    part_min: u64,
    // Loading.
    fd: i32,
    /// One byte past the ceiling, so a file that fills it exactly is told
    /// apart from one that runs past it.
    file: [u8; CREDS_FILE_MAX + 1],
    file_len: usize,
    creds: [Cred; MAX_CREDENTIALS],
    cred_count: usize,
    /// Completions holding part lists.
    completions: usize,
    present_at: usize,
    reclaim_at: usize,
    reclaim_cursor: [u8; NAME_MAX],
    reclaim_cursor_len: usize,
    // Serving.
    ex: [Exchange; MAX_EXCHANGES],
    uploads: [Upload; MAX_UPLOADS],
    sweep_at: u64,
    request_seq: u64,
    rec: [u8; RECORD_MAX],
    held: bool,
    held_len: usize,
    /// Upload ids whose staging is still to be removed.
    reap: [[u8; S3_UPLOAD_ID_LEN]; MAX_UPLOADS],
    reap_bucket: [[u8; S3_BUCKET_MAX]; MAX_UPLOADS],
    reap_bucket_len: [u8; MAX_UPLOADS],
    reap_cred: [u8; MAX_UPLOADS],
    reap_len: usize,
    page: [u8; LIST_PAGE_BUF],
    // Telemetry, in `[observability].metrics` order.
    tlm_bytes_in: u64,
    tlm_bytes_out: u64,
    tlm_requests: u64,
    tlm_errors: u64,
    tlm_aborts: u64,
    tlm_refused: u64,
    steps: u32,
}

/// Steps between telemetry reports.
const TLM_PERIOD: u32 = 5000;

unsafe fn report(s: &mut State) {
    s.steps = s.steps.wrapping_add(1);
    if !s.steps.is_multiple_of(TLM_PERIOD) || !dev_telemetry_enabled(&*s.syscalls) {
        return;
    }
    let sys = &*s.syscalls;
    let me = dev_self_index(sys);
    if me < 0 {
        return;
    }
    let t = dev_micros(sys);
    let counter = abi::contracts::telemetry::METRIC_COUNTER;
    let values = [
        s.tlm_bytes_in,
        s.tlm_bytes_out,
        s.tlm_requests,
        s.tlm_errors,
        s.tlm_aborts,
        s.tlm_refused,
    ];
    for (id, v) in values.iter().enumerate() {
        dev_telemetry_metric(sys, -1, me as u16, t, counter, id as u16, *v);
    }
}

// ── Params ────────────────────────────────────────────────────────────────

define_params! {
    State;

    // The credentials file, read through the `fs` contract.
    1, credentials, str, 0 => |s, d, len| {
        s.creds_path_bad = len > s.creds_path.len();
        if !s.creds_path_bad {
            core::ptr::copy_nonoverlapping(d, s.creds_path.as_mut_ptr(), len);
            s.creds_path_len = len;
        }
    };
    // The region signatures must be scoped to.
    2, region, str, 0 => |s, d, len| {
        s.region_bad = len > s.region.len();
        if !s.region_bad {
            core::ptr::copy_nonoverlapping(d, s.region.as_mut_ptr(), len);
            s.region_len = len;
        }
    };
    // The mesh roots the credentials' chains verify against: one or two
    // 64-hex Ed25519 keys, comma-separated — the roots the provider holds.
    3, mesh_roots, str, 0 => |s, d, len| {
        // The default is no roots, which construction refuses.
        s.roots_len = 0;
        s.roots_bad = false;
        if len == 0 {
            return;
        }
        let v = core::slice::from_raw_parts(d, len);
        for item in v.split(|&c| c == b',') {
            if item.len() != 64 || s.roots_len == cap::MAX_ROOTS {
                s.roots_bad = true;
                return;
            }
            let mut k = [0u8; 32];
            for i in 0..32 {
                match (sv4_hexval(item[2 * i]), sv4_hexval(item[2 * i + 1])) {
                    (Some(h), Some(l)) => k[i] = (h << 4) | l,
                    _ => {
                        s.roots_bad = true;
                        return;
                    }
                }
            }
            s.roots[s.roots_len] = k;
            s.roots_len += 1;
        }
    };
    // Largest object, in MiB; at most 5 TiB.
    4, max_object_mib, u32, 5120 => |s, d, len| {
        let v = p_u32(d, len, 0, 5120);
        s.object_bad = v == 0 || v > OBJECT_CEILING_MIB;
        s.max_object = (v as u64) << 20;
    };
    // Smallest part but the last, in KiB.
    5, part_min_kib, u32, 5120 => |s, d, len| {
        s.part_min = (p_u32(d, len, 0, 5120) as u64) << 10;
    };
}

// ── PIC entry points ──────────────────────────────────────────────────────

#[cfg_attr(not(feature = "host-test"), no_mangle)]
#[link_section = ".text.module_state_size"]
pub extern "C" fn module_state_size() -> u32 {
    core::mem::size_of::<State>() as u32
}

/// The heap the module may hold at once: every exchange's response record
/// and listing page, and every completion's part list, with a quarter again
/// for the allocator's rounding and headers. An allocation the arena cannot
/// meet is answered `503 SlowDown`.
/// One listed part's entity tag in a completion's list.
const PART_ETAG_STRIDE: usize = 1 + ETAG_MAX;

#[cfg_attr(not(feature = "host-test"), no_mangle)]
#[link_section = ".text.module_arena_size"]
pub extern "C" fn module_arena_size() -> u32 {
    let per_exchange = RECORD_MAX + LIST_PAGE_BUF;
    let per_completion = S3_PART_NUMBER_MAX as usize * (4 + PART_ETAG_STRIDE);
    let need = MAX_EXCHANGES * per_exchange + MAX_COMPLETIONS * per_completion;
    (need + need / 4) as u32
}

#[cfg_attr(not(feature = "host-test"), no_mangle)]
#[link_section = ".text.module_init"]
pub extern "C" fn module_init(_syscalls: *const c_void) {}

/// Construction is refused when a parameter is malformed: no credentials
/// path, roots that do not parse, an object ceiling past 5 TiB. A server that
/// could not enforce authority must not start rather than start open.
#[cfg_attr(not(feature = "host-test"), no_mangle)]
#[link_section = ".text.module_new"]
pub extern "C" fn module_new(
    _in_chan: i32,
    _out_chan: i32,
    _ctrl_chan: i32,
    params: *const u8,
    params_len: usize,
    state: *mut u8,
    state_size: usize,
    syscalls: *const c_void,
) -> i32 {
    if state.is_null() || state_size < core::mem::size_of::<State>() || syscalls.is_null() {
        return -1;
    }
    // SAFETY: `state` was null- and size-checked; the kernel zeroes at least
    // `size_of::<State>()` bytes, and an all-zero `State` is valid.
    let s = unsafe { &mut *(state as *mut State) };
    s.syscalls = syscalls as *const SyscallTable;
    // SAFETY: `syscalls` is non-null and the kernel's table for this instance.
    let sys = unsafe { &*s.syscalls };
    // SAFETY: syscall-table wrappers on ports this manifest declares.
    s.request_in = unsafe { dev_channel_port(sys, 0, 0) };
    // SAFETY: as above.
    s.response_out = unsafe { dev_channel_port(sys, 1, 0) };
    s.max_object = 5120 << 20;
    s.part_min = 5120 << 10;
    s.fd = -1;
    s.creds = [CRED_EMPTY; MAX_CREDENTIALS];
    s.uploads = [UPLOAD_EMPTY; MAX_UPLOADS];
    for e in s.ex.iter_mut() {
        e.phase = Phase::Free;
        e.list = LIST_EMPTY;
        e.out = core::ptr::null_mut();
        e.parts = core::ptr::null_mut();
        e.part_etags = core::ptr::null_mut();
    }
    let is_tlv = !params.is_null() && params_len >= 4;
    // SAFETY: `params` is valid for `params_len` bytes per the ABI.
    unsafe {
        if is_tlv && *params == 0xFE && *params.add(1) == 0x01 {
            parse_tlv(s, params, params_len);
        } else {
            set_defaults(s);
        }
    }
    if s.object_bad {
        // SAFETY: the syscall table was set from a non-null pointer above.
        unsafe { log(s, b"[s3_serve] max_object_mib must be 1 to 5242880") };
        return -22;
    }
    if s.region_bad {
        // SAFETY: the syscall table was set from a non-null pointer above.
        unsafe { log(s, b"[s3_serve] region is at most 32 bytes") };
        return -22;
    }
    if s.creds_path_bad {
        // SAFETY: the syscall table was set from a non-null pointer above.
        unsafe { log(s, b"[s3_serve] credentials path is at most 256 bytes") };
        return -22;
    }
    if s.creds_path_len == 0 || s.roots_len == 0 || s.roots_bad {
        // SAFETY: the syscall table was set from a non-null pointer above.
        unsafe {
            log(
                s,
                b"[s3_serve] credentials and mesh_roots are required and must parse",
            )
        };
        return -22;
    }
    if s.region_len == 0 {
        s.region[..9].copy_from_slice(b"us-east-1");
        s.region_len = 9;
    }
    s.boot = Boot::Load;
    0
}

#[cfg_attr(not(feature = "host-test"), no_mangle)]
#[link_section = ".text.module_step"]
pub extern "C" fn module_step(state: *mut u8) -> i32 {
    if state.is_null() {
        return -1;
    }
    // SAFETY: the kernel passes the state it validated in `module_new` and
    // steps this module single-threaded.
    let s = unsafe { &mut *(state as *mut State) };
    if s.syscalls.is_null() {
        return -1;
    }
    // SAFETY: every syscall below goes through the table set in `module_new`.
    unsafe {
        match s.boot {
            Boot::Load => load(s),
            Boot::Verify => verify(s),
            Boot::Present => present(s),
            Boot::Reclaim => reclaim(s),
            Boot::Probe => probe(s),
            Boot::Serving | Boot::Failed => {}
        }
        report(s);
        let mut worked = take_records(s);
        if s.boot == Boot::Serving {
            for i in 0..MAX_EXCHANGES {
                worked |= drive(s, i);
            }
            sweep(s);
        }
        if worked {
            2
        } else {
            0
        }
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────

unsafe fn log(s: &State, msg: &[u8]) {
    dev_log(&*s.syscalls, 2, msg.as_ptr(), msg.len());
}

unsafe fn call(sys: *const SyscallTable, handle: i32, op: u32, arg: *mut u8, len: usize) -> i32 {
    ((*sys).provider_call)(handle, op, arg, len)
}

unsafe fn now_ms(s: &State) -> u64 {
    dev_millis(&*s.syscalls)
}

/// The trusted wall clock, or `None` when the platform does not vouch for
/// one.
unsafe fn clock(s: &State) -> Option<cap::Clock> {
    cap::Clock::from_trusted(&dev_trusted_unix(&*s.syscalls))
}

struct Crypto;

impl cap::CapCrypto for Crypto {
    fn sha256(&self, data: &[u8]) -> [u8; 32] {
        sha256(data)
    }
    fn ed25519_verify(&self, key: &[u8; 32], msg: &[u8], sig: &[u8; 64]) -> bool {
        ed25519_verify(key, msg, sig)
    }
}

// ── Coming up ─────────────────────────────────────────────────────────────

/// Read the credentials file through the `fs` contract.
unsafe fn load(s: &mut State) {
    use abi::contracts::storage::fs;
    if s.fd < 0 {
        let fd = call(
            s.syscalls,
            -1,
            fs::OPEN,
            s.creds_path.as_mut_ptr(),
            s.creds_path_len,
        );
        if fd == errno::EAGAIN {
            return;
        }
        if fd < 0 {
            log(s, b"[s3_serve] credentials file cannot be opened");
            s.boot = Boot::Failed;
            return;
        }
        s.fd = fd;
    }
    let room = CREDS_FILE_MAX + 1 - s.file_len;
    if s.file_len > CREDS_FILE_MAX {
        log(s, b"[s3_serve] credentials file is past its ceiling");
        call(s.syscalls, s.fd, fs::CLOSE, core::ptr::null_mut(), 0);
        s.boot = Boot::Failed;
        return;
    }
    let n = call(
        s.syscalls,
        s.fd,
        fs::READ,
        s.file.as_mut_ptr().add(s.file_len),
        room,
    );
    if n == errno::EAGAIN {
        return;
    }
    if n < 0 {
        log(s, b"[s3_serve] credentials file cannot be read");
        s.boot = Boot::Failed;
        return;
    }
    if n > 0 {
        s.file_len += n as usize;
        return;
    }
    call(s.syscalls, s.fd, fs::CLOSE, core::ptr::null_mut(), 0);
    s.fd = -1;
    if !parse_creds(s) {
        s.boot = Boot::Failed;
        return;
    }
    s.boot = Boot::Verify;
}

/// Parse every line; any line that does not parse refuses the whole file.
unsafe fn parse_creds(s: &mut State) -> bool {
    let file = core::slice::from_raw_parts(s.file.as_ptr(), s.file_len);
    for line in file.split(|&c| c == b'\n') {
        let Some(parsed) = s3_cred_line(line) else {
            continue;
        };
        let Ok(l) = parsed else {
            log(s, b"[s3_serve] a credentials line does not parse");
            return false;
        };
        if s.cred_count == MAX_CREDENTIALS {
            log(s, b"[s3_serve] more credentials than the module holds");
            return false;
        }
        if s.creds[..s.cred_count]
            .iter()
            .any(|c| c.ak() == l.access_key)
        {
            log(s, b"[s3_serve] an access key appears twice");
            return false;
        }
        let mut c = CRED_EMPTY;
        c.access_key[..l.access_key.len()].copy_from_slice(l.access_key);
        c.ak_len = l.access_key.len() as u8;
        c.secret[..l.secret.len()].copy_from_slice(l.secret);
        c.secret_len = l.secret.len() as u8;
        if l.scope.len() > NAME_MAX {
            return false;
        }
        c.scope[..l.scope.len()].copy_from_slice(l.scope);
        c.scope_len = l.scope.len() as u8;
        match cap::decode_text(l.chain, &mut c.chain) {
            Some(n) => c.chain_len = n as u16,
            None => {
                log(s, b"[s3_serve] a capability is not fxcap1 text");
                return false;
            }
        }
        if !l.peer.is_empty() {
            for (i, p) in l.peer.chunks(2).enumerate() {
                match (
                    p.first().and_then(|&h| sv4_hexval(h)),
                    p.get(1).and_then(|&l| sv4_hexval(l)),
                ) {
                    (Some(h), Some(lo)) => c.peer[i] = (h << 4) | lo,
                    _ => return false,
                }
            }
            c.peer_len = (l.peer.len() / 2) as u8;
        }
        s.creds[s.cred_count] = c;
        s.cred_count += 1;
    }
    if s.cred_count == 0 {
        log(s, b"[s3_serve] the credentials file holds no credential");
        return false;
    }
    true
}

/// Verify every chain: against the roots, by the trusted clock, for the
/// object its scope names. Waits while no clock is trusted; refuses to serve
/// on any chain that does not verify.
unsafe fn verify(s: &mut State) {
    let Some(clk) = clock(s) else {
        return;
    };
    for i in 0..s.cred_count {
        let c = &s.creds[i];
        let Some(object) = obj::grant::scope_object(&Crypto, c.scope()) else {
            log(s, b"[s3_serve] a credential's scope is not a scope");
            s.boot = Boot::Failed;
            return;
        };
        let chain = &c.chain[..c.chain_len as usize];
        match cap::verify(&Crypto, chain, &s.roots[..s.roots_len], Some(clk), None) {
            Ok(g) if g.object_id == object => {}
            _ => {
                log(s, b"[s3_serve] a credential's capability does not verify");
                s.boot = Boot::Failed;
                return;
            }
        }
    }
    s.boot = Boot::Present;
}

/// Present each chain to the provider; its grant is what every operation for
/// that key runs under. A provider that keeps no authority (`ENOSYS`) is
/// refused: the scope would be enforced by nothing.
unsafe fn present(s: &mut State) {
    while s.present_at < s.cred_count {
        let i = s.present_at;
        let mut arg = [0u8; 3 + NAME_MAX + 2 + cap::MAX_CHAIN_BYTES];
        let c = &s.creds[i];
        let Some(n) =
            obj::grant::encode_present(&mut arg, c.scope(), &c.chain[..c.chain_len as usize])
        else {
            s.boot = Boot::Failed;
            return;
        };
        let rc = call(s.syscalls, -1, obj::PRESENT, arg.as_mut_ptr(), n);
        if rc == errno::EAGAIN {
            return;
        }
        if rc < 0 {
            if rc == errno::ENOSYS {
                log(
                    s,
                    b"[s3_serve] the storage provider keeps no authority; refusing to serve",
                );
            } else {
                log(
                    s,
                    b"[s3_serve] the storage provider refused a credential's capability",
                );
            }
            s.boot = Boot::Failed;
            return;
        }
        s.creds[i].grant = rc;
        s.present_at += 1;
    }
    s.boot = Boot::Reclaim;
}

/// Remove the staging of uploads that did not survive a restart: everything
/// under each bucket's `u/`. One page per step.
unsafe fn reclaim(s: &mut State) {
    while s.reclaim_at < s.cred_count {
        let c = s.creds[s.reclaim_at];
        // A scope narrower than its bucket cannot stage uploads.
        if c.scope() != {
            let b = c.bucket();
            &c.scope[..b.len() + 1]
        } {
            s.reclaim_at += 1;
            s.reclaim_cursor_len = 0;
            continue;
        }
        let mut prefix = [0u8; NAME_MAX];
        let Some(pl) = s3_join_bytes(&mut prefix, &[c.bucket(), S3_UPLOADS]) else {
            s.reclaim_at += 1;
            continue;
        };
        let cursor = s.reclaim_cursor;
        let page = list_page(
            s,
            c.grant,
            &prefix[..pl],
            &cursor[..s.reclaim_cursor_len],
            64,
            LIST_PAGE_BUF,
        );
        let Ok((page_len, _)) = page else {
            if page == Err(errno::EAGAIN) {
                return;
            }
            // A bucket the grant cannot list has nothing of ours to reclaim.
            s.reclaim_at += 1;
            s.reclaim_cursor_len = 0;
            continue;
        };
        let mut next = [0u8; NAME_MAX];
        let mut next_len = 0usize;
        let mut last = true;
        {
            let page_bytes = core::slice::from_raw_parts(s.page.as_ptr(), page_len);
            if let Some(p) = obj::list::decode_page(page_bytes) {
                for e in p.entries() {
                    let mut arg = [0u8; NAME_MAX + 32];
                    let mut fence = [0u8; WIRE_MAX_LEN];
                    if let Some(n) = delete_arg(&mut arg, e.key, &mut fence) {
                        let _ = obj::write_answer(call(
                            s.syscalls,
                            c.grant,
                            obj::DELETE,
                            arg.as_mut_ptr(),
                            n,
                        ));
                    }
                }
                last = p.is_last();
                next_len = p.cursor().len().min(NAME_MAX);
                next[..next_len].copy_from_slice(&p.cursor()[..next_len]);
            }
        }
        if last {
            s.reclaim_at += 1;
            s.reclaim_cursor_len = 0;
        } else {
            s.reclaim_cursor[..next_len].copy_from_slice(&next[..next_len]);
            s.reclaim_cursor_len = next_len;
        }
        return;
    }
    s.boot = Boot::Probe;
}

/// Encode a `PUT_STREAMED_OPEN` argument block into `arg`, returning its
/// length. The one place this layout is written: three callers open a streamed
/// put — an object, a part, and the probe below — and a second spelling of a
/// wire layout is how two of them drift apart.
///
/// `declared` is the expected size, a hint the provider may ignore; `etag` is
/// empty unless `precondition` is `ETAG`.
fn encode_put_open(
    arg: &mut [u8],
    key: &[u8],
    content_type: &[u8],
    declared: u64,
    precondition: u8,
    etag: &[u8],
) -> Option<usize> {
    let n = 2 + key.len() + 1 + content_type.len() + 8 + 2 + etag.len();
    if n > arg.len() || key.len() > u16::MAX as usize || content_type.len() > u8::MAX as usize {
        return None;
    }
    let mut p = 0usize;
    arg[p..p + 2].copy_from_slice(&(key.len() as u16).to_le_bytes());
    p += 2;
    arg[p..p + key.len()].copy_from_slice(key);
    p += key.len();
    arg[p] = content_type.len() as u8;
    p += 1;
    arg[p..p + content_type.len()].copy_from_slice(content_type);
    p += content_type.len();
    arg[p..p + 8].copy_from_slice(&declared.to_le_bytes());
    p += 8;
    arg[p] = precondition;
    arg[p + 1] = etag.len() as u8;
    p += 2;
    arg[p..p + etag.len()].copy_from_slice(etag);
    Some(p + etag.len())
}

/// Ask the provider whether it can take a streamed write, before accepting a
/// request that depends on one.
///
/// Every object this module writes — PutObject and UploadPart alike — goes
/// through `PUT_STREAMED_OPEN`/`WRITE`/`COMMIT`, because an object runs to
/// `OBJECT_CEILING_MIB` and nothing here holds one whole. A provider without
/// that sequence can still answer the reads, the deletes and every refusal,
/// so it looks healthy from outside while no write it is given ever lands.
/// Serving in that state turns one missing provider operation into a `501`
/// per request; refusing here states it once.
///
/// The probe opens and aborts, so it stages nothing and commits nothing. Only
/// `ENOSYS` is fatal: any other refusal is the provider exercising a judgement
/// about this key, which is proof enough that it implements the operation.
unsafe fn probe(s: &mut State) {
    let c = &s.creds[0];
    let scope = c.scope();
    let mut key = [0u8; NAME_MAX];
    let Some(kl) = s3_join_bytes(&mut key, &[scope, b"probe"]) else {
        s.boot = Boot::Failed;
        log(
            s,
            b"[s3_serve] a credential's scope leaves no room for a key",
        );
        return;
    };
    let mut arg = [0u8; NAME_MAX + 32];
    let Some(p) = encode_put_open(&mut arg, &key[..kl], &[], 0, obj::precondition::ANY, &[]) else {
        s.boot = Boot::Failed;
        log(
            s,
            b"[s3_serve] a credential's scope leaves no room for a key",
        );
        return;
    };
    let h = call(
        s.syscalls,
        c.grant,
        obj::PUT_STREAMED_OPEN,
        arg.as_mut_ptr(),
        p,
    );
    if h == errno::EAGAIN {
        return;
    }
    if h == errno::ENOSYS {
        log(
            s,
            b"[s3_serve] the storage provider cannot take a streamed write; refusing to serve",
        );
        s.boot = Boot::Failed;
        return;
    }
    if h >= 0 {
        call(
            s.syscalls,
            h,
            obj::PUT_STREAMED_ABORT,
            core::ptr::null_mut(),
            0,
        );
    }
    s.boot = Boot::Serving;
    log(s, b"[s3_serve] serving");
}

fn s3_join_bytes(out: &mut [u8], parts: &[&[u8]]) -> Option<usize> {
    let mut n = 0usize;
    for p in parts {
        let end = n.checked_add(p.len())?;
        if end > out.len() {
            return None;
        }
        out[n..end].copy_from_slice(p);
        n = end;
    }
    Some(n)
}

/// One `LIST` page into `s.page`: `(length, fence)` or an errno.
unsafe fn list_page(
    s: &mut State,
    grant: i32,
    prefix: &[u8],
    cursor: &[u8],
    max_keys: u16,
    out_cap: usize,
) -> Result<(usize, ()), i32> {
    let mut fence = [0u8; WIRE_MAX_LEN];
    let req = obj::list::Request {
        prefix,
        cursor,
        max_keys,
        out_ptr: s.page.as_mut_ptr() as u64,
        out_cap: out_cap.min(LIST_PAGE_BUF) as u32,
        fence_out_ptr: fence.as_mut_ptr() as u64,
        fence_out_cap: WIRE_MAX_LEN as u16,
    };
    let mut arg = [0u8; obj::list::REQUEST_FIXED_LEN + 2 * NAME_MAX];
    let Some(n) = obj::list::encode_request(&mut arg, &req) else {
        return Err(errno::EINVAL);
    };
    let rc = call(s.syscalls, grant, obj::LIST, arg.as_mut_ptr(), n);
    if rc < 0 {
        Err(rc)
    } else {
        Ok((rc as usize, ()))
    }
}

/// A `DELETE` request, unconditional.
fn delete_arg(arg: &mut [u8], key: &[u8], fence: &mut [u8; WIRE_MAX_LEN]) -> Option<usize> {
    let n = 2 + key.len() + 2 + 10;
    if n > arg.len() || key.len() > u16::MAX as usize {
        return None;
    }
    arg[..2].copy_from_slice(&(key.len() as u16).to_le_bytes());
    arg[2..2 + key.len()].copy_from_slice(key);
    let p = 2 + key.len();
    arg[p] = obj::precondition::ANY;
    arg[p + 1] = 0;
    arg[p + 2..p + 10].copy_from_slice(&(fence.as_mut_ptr() as u64).to_le_bytes());
    arg[p + 10..p + 12].copy_from_slice(&(WIRE_MAX_LEN as u16).to_le_bytes());
    Some(p + 12)
}

// ── Records in ────────────────────────────────────────────────────────────

/// Read the records `http` wrote and hand each to its exchange. A HEAD that
/// finds no free exchange is answered `503 SlowDown` at once, so a full table
/// never holds back the records of exchanges already running.
unsafe fn take_records(s: &mut State) -> bool {
    let sys = &*s.syscalls;
    let mut worked = false;
    for _ in 0..16 {
        if !s.held {
            let ready = (sys.channel_poll)(s.request_in, POLL_IN);
            if ready <= 0 || (ready as u32 & POLL_IN) == 0 {
                return worked;
            }
            let n = (sys.channel_read)(s.request_in, s.rec.as_mut_ptr(), RECORD_MAX);
            if n <= 0 {
                return worked;
            }
            s.held = true;
            s.held_len = n as usize;
        }
        if !take(s) {
            return worked;
        }
        s.held = false;
        worked = true;
    }
    worked
}

/// Take the held record. False when it must wait (the answer to a refused
/// HEAD could not be written yet).
unsafe fn take(s: &mut State) -> bool {
    let raw: &[u8] = core::slice::from_raw_parts(s.rec.as_ptr(), s.held_len);
    let Some(rec) = parse_request(raw) else {
        return true;
    };
    match rec {
        Record::Head(h) => {
            let Some(i) = s.ex.iter().position(|e| e.phase == Phase::Free) else {
                // Counted once, when the refusal goes: a HEAD held back by a
                // full `response_out` is the same refusal asked again.
                let sent = refuse_now(s, &h.id, h.resp_credit);
                if sent {
                    s.tlm_refused = s.tlm_refused.wrapping_add(1);
                }
                return sent;
            };
            if s.boot != Boot::Serving {
                return refuse_now(s, &h.id, h.resp_credit);
            }
            if !begin(s, i, &h) {
                return refuse_now(s, &h.id, h.resp_credit);
            }
            s.tlm_requests = s.tlm_requests.wrapping_add(1);
            true
        }
        Record::Body { id, flags, data } => {
            s.tlm_bytes_in = s.tlm_bytes_in.wrapping_add(data.len() as u64);
            if let Some(i) = find(s, &id) {
                let last = flags & flag::MORE == 0;
                let data: &[u8] = core::slice::from_raw_parts(data.as_ptr(), data.len());
                body(s, i, data, last);
            }
            true
        }
        Record::Credit { id, bytes } => {
            if let Some(i) = find(s, &id) {
                s.ex[i].resp_credit = s.ex[i].resp_credit.saturating_add(bytes);
            }
            true
        }
        Record::Abort { id, .. } => {
            if let Some(i) = find(s, &id) {
                end(s, i, false);
            }
            true
        }
        Record::Datagram { .. } | Record::Link { .. } => true,
    }
}

/// The next `x-amz-request-id`: the request count, in hex.
fn next_request_id(s: &mut State) -> [u8; 16] {
    s.request_seq = s.request_seq.wrapping_add(1);
    let seq = s.request_seq;
    let mut rid = [0u8; 16];
    for (k, b) in rid.iter_mut().enumerate() {
        let nib = ((seq >> (60 - 4 * k)) & 0xf) as u8;
        *b = if nib < 10 {
            b'0' + nib
        } else {
            b'A' + nib - 10
        };
    }
    rid
}

unsafe fn find(s: &State, id: &ExchangeId) -> Option<usize> {
    s.ex.iter()
        .position(|e| e.phase != Phase::Free && e.id == *id)
}

/// Answer a HEAD with no exchange to serve it: `503 SlowDown`, or
/// `ServiceUnavailable` while the module is not serving. Written straight
/// away; false when `response_out` is full, and the HEAD waits.
unsafe fn refuse_now(s: &mut State, id: &ExchangeId, credit: u32) -> bool {
    let err = if s.boot == Boot::Serving {
        S3Err::SlowDown
    } else {
        S3Err::ServiceUnavailable
    };
    let rid = next_request_id(s);
    let mut body = [0u8; 512];
    let mut o = S3Out::new(&mut body);
    s3_error_xml(err, b"Try again later.", b"", &rid, &mut o);
    let len = if (o.len as u32) <= credit && !o.over {
        o.len
    } else {
        0
    };
    let mut hdr = [0u8; 64];
    let mut h = S3Out::new(&mut hdr);
    h.put(b"retry-after: 1\r\nx-amz-request-id: ");
    h.put(&rid);
    h.put(b"\r\n");
    let hl = h.len;
    let mut rec = [0u8; 1024];
    let head = ResponseHead {
        id: *id,
        flags: 0,
        status: err.status(),
        content_type: b"application/xml",
        headers: &hdr[..hl],
        body: &body[..len],
    };
    let Some(n) = write_response_head(&head, &mut rec) else {
        return true;
    };
    ((*s.syscalls).channel_write)(s.response_out, rec.as_ptr(), n) > 0
}

// ── Opening an exchange ───────────────────────────────────────────────────

/// Open exchange `i` for a request HEAD. False, with the exchange left free,
/// when there is no room to answer it from; the caller refuses the HEAD.
unsafe fn begin(s: &mut State, i: usize, h: &RequestHead<'_>) -> bool {
    let e = &mut s.ex[i];
    e.phase = Phase::Answer;
    e.id = h.id;
    e.method = h.method;
    // A body is open while BODY records follow it, or while the HEAD's own
    // inline bytes are still to be taken below.
    let more = h.flags & flag::MORE != 0;
    e.body_open = more || !h.body.is_empty();
    e.credit_out = 0;
    e.credit_owed = 0;
    e.resp_credit = h.resp_credit;
    e.head_sent = false;
    e.name_len = 0;
    e.bucket_len = 0;
    e.upload_slot = -1;
    e.part = 0;
    e.payload = Payload::Unsigned;
    e.hasher = None;
    e.chunked = None;
    e.declared = 0;
    e.received = 0;
    e.handle = -1;
    e.arg_len = 0;
    e.etag_len = 0;
    e.list = LIST_EMPTY;
    e.parts_len = 0;
    e.part_at = 0;
    e.parts_reader = None;
    e.parts_bad = None;
    e.out_state = Out::Idle;
    e.out_len = 0;
    e.out_final = false;
    s.ex[i].request_id = next_request_id(s);
    if s.ex[i].out.is_null() {
        s.ex[i].out = heap_alloc(&*s.syscalls, RECORD_MAX as u32);
        if s.ex[i].out.is_null() {
            s.ex[i].phase = Phase::Free;
            return false;
        }
    }
    let target: &[u8] = core::slice::from_raw_parts(h.target.as_ptr(), h.target.len());
    let headers: &[u8] = core::slice::from_raw_parts(h.headers.as_ptr(), h.headers.len());
    let peer: &[u8] = core::slice::from_raw_parts(h.peer.as_ptr(), h.peer.len());
    if let Err(err) = dispatch(s, i, target, headers, peer) {
        fail(s, i, err);
    }
    // The body bytes the HEAD carried, taken as the first body record. They
    // spent no credit, so the credit their taking owes back is not owed.
    if !h.body.is_empty() && s.ex[i].phase != Phase::Free {
        let inline: &[u8] = core::slice::from_raw_parts(h.body.as_ptr(), h.body.len());
        s.tlm_bytes_in = s.tlm_bytes_in.wrapping_add(inline.len() as u64);
        let credit_out = s.ex[i].credit_out;
        body(s, i, inline, !more);
        let e = &mut s.ex[i];
        e.credit_out = credit_out;
        e.credit_owed = e.credit_owed.saturating_sub(inline.len() as u32);
    }
    true
}

/// Authenticate the request and start the operation it asks for.
unsafe fn dispatch(
    s: &mut State,
    i: usize,
    target: &[u8],
    headers: &[u8],
    peer: &[u8],
) -> Result<(), S3Err> {
    let method = exchange::method_name(s.ex[i].method);
    let r = s3_resource(target);
    let op = s3_classify(method, &r);
    s.ex[i].op = op;
    let cred = authenticate(s, i, method, target, headers, peer)?;
    s.ex[i].cred = cred as u8;
    match op {
        S3Op::MethodNotAllowed => return Err(S3Err::MethodNotAllowed),
        S3Op::NotImplemented => return Err(S3Err::NotImplemented),
        _ => {}
    }
    // Requests this server could only accept by ignoring part of them.
    if sv4_header(headers, b"x-amz-copy-source").is_some()
        || sv4_header(headers, b"content-md5").is_some()
        || headers_have_prefix(headers, b"x-amz-checksum-")
        || sv4_header(headers, b"x-amz-trailer").is_some()
    {
        return Err(S3Err::NotImplemented);
    }
    if op == S3Op::ListBuckets {
        return list_buckets(s, i);
    }
    if !s3_bucket_valid(r.bucket) {
        return Err(S3Err::InvalidBucketName);
    }
    s.ex[i].bucket_len = r.bucket.len();
    match op {
        S3Op::HeadBucket | S3Op::CreateBucket | S3Op::GetBucketLocation => {
            set_name(s, i, r.bucket, b"")?;
            s.ex[i].phase = Phase::BucketProbe;
            Ok(())
        }
        S3Op::DeleteBucket => Err(S3Err::NotImplemented),
        S3Op::ListObjects | S3Op::ListObjectsV2 => {
            set_name(s, i, r.bucket, b"")?;
            begin_list(s, i, r.bucket, r.query, op)
        }
        S3Op::PutObject => {
            set_key(s, i, r.bucket, r.key)?;
            begin_put(s, i, headers, false)
        }
        S3Op::GetObject | S3Op::HeadObject => {
            set_key(s, i, r.bucket, r.key)?;
            begin_read(s, i, headers)
        }
        S3Op::DeleteObject => {
            set_key(s, i, r.bucket, r.key)?;
            s.ex[i].phase = Phase::Delete;
            Ok(())
        }
        S3Op::CreateMultipartUpload => {
            set_key(s, i, r.bucket, r.key)?;
            begin_create_upload(s, i)
        }
        S3Op::UploadPart => {
            set_key(s, i, r.bucket, r.key)?;
            let part = sv4_query_param(r.query, b"partNumber")
                .and_then(sv4_digits)
                .and_then(|v| u32::try_from(v).ok())
                .ok_or(S3Err::InvalidArgument)?;
            if part == 0 || part > S3_PART_NUMBER_MAX {
                return Err(S3Err::InvalidArgument);
            }
            bind_upload(s, i, r.query)?;
            s.ex[i].part = part;
            begin_put(s, i, headers, true)
        }
        S3Op::CompleteMultipartUpload => {
            set_key(s, i, r.bucket, r.key)?;
            bind_upload(s, i, r.query)?;
            begin_complete(s, i)
        }
        S3Op::AbortMultipartUpload => {
            set_key(s, i, r.bucket, r.key)?;
            bind_upload(s, i, r.query)?;
            let slot = s.ex[i].upload_slot as usize;
            s.uploads[slot].busy = true;
            s.ex[i].phase = Phase::UploadDelete;
            s.ex[i].list = LIST_EMPTY;
            Ok(())
        }
        _ => Err(S3Err::NotImplemented),
    }
}

fn headers_have_prefix(headers: &[u8], prefix: &[u8]) -> bool {
    headers
        .split(|&c| c == b'\n')
        .any(|line| line.len() >= prefix.len() && line[..prefix.len()].eq_ignore_ascii_case(prefix))
}

/// Verify the request's signature, header or presigned form, and return the
/// credential it was made with.
unsafe fn authenticate(
    s: &mut State,
    i: usize,
    method: &[u8],
    target: &[u8],
    headers: &[u8],
    peer: &[u8],
) -> Result<usize, S3Err> {
    let (_, query) = sv4_split_target(target);
    let mut cred_buf = [0u8; 256];
    let header_form = sv4_header(headers, b"authorization").is_some();
    let auth = if header_form {
        sv4_parse_header_auth(headers)
    } else {
        sv4_parse_presigned(query, &mut cred_buf)
    }
    .map_err(|e| match e {
        Sv4Error::Missing => S3Err::AccessDenied,
        Sv4Error::HeaderMissing => S3Err::AccessDenied,
        _ if header_form => S3Err::AuthorizationHeaderMalformed,
        _ => S3Err::AuthorizationQueryParametersError,
    })?;
    let Some(ci) = (0..s.cred_count).find(|&k| s.creds[k].ak() == auth.access_key) else {
        return Err(S3Err::InvalidAccessKeyId);
    };
    let region = &s.region[..s.region_len];
    if auth.region != region
        || auth.service != b"s3"
        || auth.amz_date.get(..8) != Some(auth.scope_date)
    {
        return Err(if header_form {
            S3Err::AuthorizationHeaderMalformed
        } else {
            S3Err::AuthorizationQueryParametersError
        });
    }
    let t = sv4_parse_amz_date(auth.amz_date).ok_or(S3Err::AccessDenied)?;
    let Some(clk) = clock(s) else {
        return Err(S3Err::ServiceUnavailable);
    };
    if !sv4_within_skew(t, clk.now, clk.uncertainty) {
        // A presigned URL is judged by its lifetime, not by skew, once it is
        // not from the future.
        let future = t > clk
            .now
            .saturating_add(clk.uncertainty)
            .saturating_add(SV4_SKEW_MAX);
        if header_form || future {
            return Err(S3Err::RequestTimeTooSkewed);
        }
    }
    if let Some(exp) = auth.expires {
        if !sv4_presign_live(t, exp, clk.now, clk.uncertainty) {
            return Err(S3Err::AccessDenied);
        }
    }
    let payload: &[u8] = if header_form {
        sv4_header(headers, b"x-amz-content-sha256").ok_or(S3Err::MissingSecurityHeader)?
    } else {
        SV4_UNSIGNED
    };
    let mut signed = [0u8; 512];
    let signed_headers: &[u8] = if header_form {
        auth.signed_headers
    } else {
        let n = sv4_decode(auth.signed_headers, &mut signed)
            .ok_or(S3Err::AuthorizationQueryParametersError)?;
        &signed[..n]
    };
    let mut scratch = [0u8; SV4_QUERY_SCRATCH];
    let ch = sv4_canonical_request_hash(
        method,
        target,
        headers,
        signed_headers,
        payload,
        !header_form,
        &mut scratch,
    )
    .map_err(|e| match e {
        // More query parameters or signed headers than are canonicalised.
        Sv4Error::TooLarge => S3Err::InvalidArgument,
        _ => S3Err::SignatureDoesNotMatch,
    })?;
    let c = &s.creds[ci];
    let key = sv4_signing_key(
        &c.secret[..c.secret_len as usize],
        auth.scope_date,
        region,
        b"s3",
    );
    let sig = sv4_signature(&key, auth.amz_date, auth.scope_date, region, b"s3", &ch);
    if !sv4_eq(&sig, auth.signature) {
        return Err(S3Err::SignatureDoesNotMatch);
    }
    // A key bound to an mTLS peer is honoured only from that peer.
    if c.peer_len > 0 && peer != &c.peer[..c.peer_len as usize] {
        return Err(S3Err::AccessDenied);
    }
    let e = &mut s.ex[i];
    e.signing_key = key;
    e.amz_date.copy_from_slice(&auth.amz_date[..16]);
    e.scope_date.copy_from_slice(auth.scope_date);
    e.seed = sig;
    e.payload = if payload == SV4_UNSIGNED {
        Payload::Unsigned
    } else if payload == SV4_STREAMING {
        Payload::Chunked
    } else if payload.len() == 64 {
        let mut d = [0u8; 32];
        for k in 0..32 {
            match (sv4_hexval(payload[2 * k]), sv4_hexval(payload[2 * k + 1])) {
                (Some(h), Some(l)) => d[k] = (h << 4) | l,
                _ => return Err(S3Err::XAmzContentSha256Mismatch),
            }
        }
        Payload::Hashed(d)
    } else {
        return Err(S3Err::NotImplemented);
    };
    Ok(ci)
}

unsafe fn set_name(s: &mut State, i: usize, bucket: &[u8], suffix: &[u8]) -> Result<(), S3Err> {
    let e = &mut s.ex[i];
    let n = s3_join_bytes(&mut e.name, &[bucket, S3_OBJECTS, suffix]).ok_or(S3Err::KeyTooLong)?;
    e.name_len = n;
    Ok(())
}

unsafe fn set_key(s: &mut State, i: usize, bucket: &[u8], key_raw: &[u8]) -> Result<(), S3Err> {
    let mut key = [0u8; NAME_MAX];
    let kl = sv4_decode(key_raw, &mut key).ok_or(S3Err::KeyTooLong)?;
    let e = &mut s.ex[i];
    let n = s3_object_name(bucket, &key[..kl], &mut e.name)?;
    e.name_len = n;
    Ok(())
}

unsafe fn bind_upload(s: &mut State, i: usize, query: &[u8]) -> Result<(), S3Err> {
    let id = sv4_query_param(query, b"uploadId").ok_or(S3Err::NoSuchUpload)?;
    let name = &s.ex[i].name[..s.ex[i].name_len];
    let slot = s
        .uploads
        .iter()
        .position(|u| u.used && &u.id[..] == id && &u.name[..u.name_len as usize] == name)
        .ok_or(S3Err::NoSuchUpload)?;
    if s.uploads[slot].busy {
        return Err(S3Err::NoSuchUpload);
    }
    s.ex[i].upload.copy_from_slice(&s.uploads[slot].id);
    s.ex[i].upload_slot = slot as i16;
    Ok(())
}

// ── Answers ───────────────────────────────────────────────────────────────

/// End exchange `i` with an S3 error: a whole `<Error>` response while
/// nothing of the response has gone, an ABORT after.
unsafe fn fail(s: &mut State, i: usize, err: S3Err) {
    s.tlm_errors = s.tlm_errors.wrapping_add(1);
    if s.ex[i].head_sent {
        abort_out(s, i);
        return;
    }
    release_handles(s, i);
    let e = &mut s.ex[i];
    let mut body = [0u8; 1024];
    let mut o = S3Out::new(&mut body);
    let rid = e.request_id;
    // The resource as the client named it, `/bucket[/key]`, never the
    // storage name it maps to.
    let name = &e.name[..e.name_len];
    let bucket = name.get(..e.bucket_len).unwrap_or(&[]);
    let mut resource = [0u8; NAME_MAX + 2];
    let mut r = S3Out::new(&mut resource);
    r.put(b"/");
    r.put(bucket);
    if let Some(key) = s3_key_of(name, bucket).filter(|k| !k.is_empty()) {
        r.put(b"/");
        r.put(key);
    }
    let resource_len = r.len;
    s3_error_xml(err, err.code(), &resource[..resource_len], &rid, &mut o);
    let len = if !o.over && (o.len as u32) <= e.resp_credit && e.method != exchange::METHOD_HEAD {
        o.len
    } else {
        0
    };
    let mut hdr = [0u8; 64];
    let mut h = S3Out::new(&mut hdr);
    h.put(b"x-amz-request-id: ");
    h.put(&rid);
    h.put(b"\r\n");
    let hl = h.len;
    stage_head(
        s,
        i,
        err.status(),
        b"application/xml",
        &hdr[..hl],
        &body[..len],
        true,
    );
    s.ex[i].phase = Phase::Answer;
}

/// Stage a response HEAD in the exchange's record buffer.
unsafe fn stage_head(
    s: &mut State,
    i: usize,
    status: u16,
    ct: &[u8],
    headers: &[u8],
    body: &[u8],
    last: bool,
) -> bool {
    let e = &mut s.ex[i];
    let out = core::slice::from_raw_parts_mut(e.out, RECORD_MAX);
    if body.len() as u64 > e.resp_credit as u64 {
        // A document past the credit `http` offered cannot be sent whole,
        // and sending part of it would be a different answer: the exchange
        // is given up, and `http` answers for it.
        if let Some(n) = exchange::write_abort(&e.id, abort::FAILED, out) {
            e.out_len = n;
            e.out_state = Out::Pending;
            e.out_final = true;
        }
        s.tlm_aborts = s.tlm_aborts.wrapping_add(1);
        return false;
    }
    let head = ResponseHead {
        id: e.id,
        flags: if last { 0 } else { flag::MORE },
        status,
        content_type: ct,
        headers,
        body,
    };
    match write_response_head(&head, out) {
        Some(n) => {
            e.out_len = n;
            e.out_state = Out::Pending;
            e.out_final = last;
            e.head_sent = true;
            e.resp_credit = e.resp_credit.saturating_sub(body.len() as u32);
            true
        }
        None => false,
    }
}

/// Stage a response BODY.
unsafe fn stage_body(s: &mut State, i: usize, data: &[u8], last: bool) {
    let e = &mut s.ex[i];
    let out = core::slice::from_raw_parts_mut(e.out, RECORD_MAX);
    if let Some(n) = write_body(&e.id, if last { 0 } else { flag::MORE }, data, out) {
        e.out_len = n;
        e.out_state = Out::Pending;
        e.out_final = last;
        e.resp_credit = e.resp_credit.saturating_sub(data.len() as u32);
    }
}

/// Write the staged record. True when it went (or nothing was staged).
unsafe fn flush(s: &mut State, i: usize) -> bool {
    let e = &mut s.ex[i];
    if e.out_state == Out::Idle {
        return true;
    }
    if ((*s.syscalls).channel_write)(s.response_out, e.out, e.out_len) > 0 {
        s.tlm_bytes_out = s.tlm_bytes_out.wrapping_add(e.out_len as u64);
        let e = &mut s.ex[i];
        e.out_state = Out::Idle;
        if e.out_final {
            end(s, i, true);
        }
        return true;
    }
    false
}

/// Tell `http` the exchange cannot finish.
unsafe fn abort_out(s: &mut State, i: usize) {
    s.tlm_aborts = s.tlm_aborts.wrapping_add(1);
    let e = &mut s.ex[i];
    let out = core::slice::from_raw_parts_mut(e.out, RECORD_MAX);
    if let Some(n) = exchange::write_abort(&e.id, abort::FAILED, out) {
        e.out_len = n;
        e.out_state = Out::Pending;
        e.out_final = true;
    }
    release_handles(s, i);
    s.ex[i].phase = Phase::Answer;
}

/// Request-body credit owed back to `http`, granted as soon as the channel
/// takes it.
unsafe fn grant(s: &mut State, i: usize) {
    let e = &mut s.ex[i];
    if e.credit_owed == 0 || !e.body_open {
        return;
    }
    let mut rec = [0u8; 32];
    if let Some(n) = write_credit(&e.id, e.credit_owed, &mut rec) {
        if ((*s.syscalls).channel_write)(s.response_out, rec.as_ptr(), n) > 0 {
            e.credit_out = e.credit_out.saturating_add(e.credit_owed);
            e.credit_owed = 0;
        }
    }
}

unsafe fn release_handles(s: &mut State, i: usize) {
    // A completion's copy holds the part it reads beside its put, in `mtime`.
    if s.ex[i].phase == Phase::CompleteCopy && s.ex[i].mtime != u64::MAX {
        call(
            s.syscalls,
            s.ex[i].mtime as i32,
            obj::CLOSE,
            core::ptr::null_mut(),
            0,
        );
        s.ex[i].mtime = u64::MAX;
    }
    let e = &mut s.ex[i];
    if e.handle >= 0 {
        match e.phase {
            Phase::PutBody | Phase::PutCommit | Phase::CompleteCopy | Phase::CompleteCommit => {
                call(
                    s.syscalls,
                    e.handle,
                    obj::PUT_STREAMED_ABORT,
                    core::ptr::null_mut(),
                    0,
                );
            }
            _ => {
                call(s.syscalls, e.handle, obj::CLOSE, core::ptr::null_mut(), 0);
            }
        }
        s.ex[i].handle = -1;
    }
}

/// Release exchange `i`. `answered` false means `http` ended it.
unsafe fn end(s: &mut State, i: usize, answered: bool) {
    if !answered {
        release_handles(s, i);
    }
    let e = &mut s.ex[i];
    if !e.list.page.is_null() {
        heap_free(&*s.syscalls, e.list.page);
        e.list.page = core::ptr::null_mut();
    }
    if !e.parts.is_null() {
        heap_free(&*s.syscalls, e.parts as *mut u8);
        e.parts = core::ptr::null_mut();
    }
    if !e.part_etags.is_null() {
        heap_free(&*s.syscalls, e.part_etags);
        e.part_etags = core::ptr::null_mut();
        s.completions -= 1;
    }
    let slot = e.upload_slot;
    if slot >= 0 {
        s.uploads[slot as usize].busy = false;
    }
    s.ex[i].phase = Phase::Free;
    s.ex[i].hasher = None;
    s.ex[i].chunked = None;
    s.ex[i].parts_reader = None;
}

// ── The exchanges' own work ───────────────────────────────────────────────

/// Move exchange `i` on by one bounded piece of work.
unsafe fn drive(s: &mut State, i: usize) -> bool {
    if s.ex[i].phase == Phase::Free {
        return false;
    }
    grant(s, i);
    if !flush(s, i) {
        return false;
    }
    if s.ex[i].phase == Phase::Free {
        return true;
    }
    match s.ex[i].phase {
        Phase::Answer => false,
        Phase::PutCommit => put_commit(s, i),
        Phase::PutHead => put_head(s, i),
        Phase::ReadHead => read_head(s, i),
        Phase::ReadOpen => read_open(s, i),
        Phase::GetBody => get_body(s, i),
        Phase::List => list_step(s, i),
        Phase::UploadCreate => upload_create(s, i),
        Phase::CompleteCheck => complete_check(s, i),
        Phase::CompleteCopy => complete_copy(s, i),
        Phase::CompleteCommit => complete_commit(s, i),
        Phase::CompleteResult => complete_result(s, i),
        Phase::UploadDelete => upload_delete(s, i),
        Phase::Delete => delete_step(s, i),
        Phase::BucketProbe => bucket_probe(s, i),
        Phase::PutBody | Phase::CompleteParts | Phase::Free => false,
    }
}

/// A body record for exchange `i`.
unsafe fn body(s: &mut State, i: usize, data: &[u8], last: bool) {
    let e = &mut s.ex[i];
    e.credit_out = e.credit_out.saturating_sub(data.len() as u32);
    if last {
        e.body_open = false;
    }
    match e.phase {
        Phase::PutBody => put_data(s, i, data, last),
        Phase::CompleteParts => complete_data(s, i, data, last),
        // A body the operation does not read: consumed, and credited so it
        // keeps moving until it ends.
        _ => {
            s.ex[i].credit_owed = s.ex[i].credit_owed.saturating_add(data.len() as u32);
        }
    }
}

// ── PUT (objects and parts) ───────────────────────────────────────────────

unsafe fn begin_put(s: &mut State, i: usize, headers: &[u8], part: bool) -> Result<(), S3Err> {
    let declared = if s.ex[i].payload == Payload::Chunked {
        sv4_header(headers, b"x-amz-decoded-content-length")
    } else {
        sv4_header(headers, b"content-length")
    }
    .and_then(sv4_digits)
    .ok_or(S3Err::MissingContentLength)?;
    let ceiling = if part { PART_SIZE_MAX } else { s.max_object };
    if declared > ceiling {
        return Err(S3Err::EntityTooLarge);
    }
    let mut precondition = obj::precondition::ANY;
    let mut etag = [0u8; 32];
    let mut etag_len = 0usize;
    if !part {
        if let Some(v) = sv4_header(headers, b"if-none-match") {
            if v != b"*" {
                return Err(S3Err::NotImplemented);
            }
            precondition = obj::precondition::ABSENT;
        }
        if let Some(v) = sv4_header(headers, b"if-match") {
            let hex = v
                .strip_prefix(b"\"")
                .and_then(|v| v.strip_suffix(b"\""))
                .unwrap_or(v);
            if hex.len() > 2 * ETAG_MAX || !hex.len().is_multiple_of(2) {
                return Err(S3Err::PreconditionFailed);
            }
            for k in 0..hex.len() / 2 {
                etag[k] = match (sv4_hexval(hex[2 * k]), sv4_hexval(hex[2 * k + 1])) {
                    (Some(h), Some(l)) => (h << 4) | l,
                    _ => return Err(S3Err::PreconditionFailed),
                };
            }
            etag_len = hex.len() / 2;
            precondition = obj::precondition::ETAG;
        }
    }
    let ct = sv4_header(headers, b"content-type").unwrap_or(b"");
    if ct.len() > CT_MAX {
        return Err(S3Err::InvalidArgument);
    }
    // The name a part is staged at.
    if part {
        let e = &mut s.ex[i];
        let bucket_len = e.bucket_len;
        let mut bucket = [0u8; S3_BUCKET_MAX];
        bucket[..bucket_len].copy_from_slice(&e.name[..bucket_len]);
        let n = s3_upload_name(&bucket[..bucket_len], &e.upload, e.part, &mut e.name)
            .ok_or(S3Err::KeyTooLong)?;
        e.name_len = n;
    }
    let e = &mut s.ex[i];
    e.declared = declared;
    e.received = 0;
    match e.payload {
        Payload::Hashed(_) => e.hasher = Some(Sha256::new()),
        Payload::Chunked => e.chunked = Some(S3Chunked::new(&e.seed)),
        Payload::Unsigned => {}
    }
    let key = &e.name[..e.name_len];
    let mut arg = [0u8; NAME_MAX + 300];
    let p = encode_put_open(&mut arg, key, ct, declared, precondition, &etag[..etag_len])
        .ok_or(S3Err::KeyTooLong)?;
    let grant = s.creds[s.ex[i].cred as usize].grant;
    let h = call(
        s.syscalls,
        grant,
        obj::PUT_STREAMED_OPEN,
        arg.as_mut_ptr(),
        p,
    );
    if h < 0 {
        return Err(s3_errno(h, false));
    }
    let e = &mut s.ex[i];
    e.handle = h;
    e.phase = Phase::PutBody;
    if e.body_open {
        e.credit_owed = BODY_WINDOW;
    } else {
        finish_put_body(s, i);
    }
    Ok(())
}

/// Body bytes for a streamed put.
unsafe fn put_data(s: &mut State, i: usize, data: &[u8], last: bool) {
    let handle = s.ex[i].handle;
    let sys = s.syscalls;
    let mut write_err = 0i32;
    let mut written = 0u64;
    // The region the chunk signatures are scoped to is the server's.
    let region_len = s.region_len;
    let mut region = [0u8; 32];
    region[..region_len].copy_from_slice(&s.region[..region_len]);
    let e = &mut s.ex[i];
    let outcome: Result<(), S3Err> = match e.payload {
        Payload::Chunked => {
            let key = S3ChunkKey {
                signing_key: &e.signing_key,
                amz_date: &e.amz_date,
                scope_date: &e.scope_date,
                region: &region[..region_len],
                service: b"s3",
            };
            match e.chunked.as_mut() {
                Some(c) => c
                    .feed(data, &key, |d| {
                        if write_err == 0 && !d.is_empty() {
                            let rc = ((*sys).provider_call)(
                                handle,
                                obj::PUT_STREAMED_WRITE,
                                d.as_ptr() as *mut u8,
                                d.len(),
                            );
                            if rc < 0 {
                                write_err = rc;
                            }
                            written += d.len() as u64;
                        }
                    })
                    .map_err(|err| match err {
                        S3ChunkErr::Signature => S3Err::SignatureDoesNotMatch,
                        S3ChunkErr::Malformed => S3Err::IncompleteBody,
                    }),
                None => Err(S3Err::InternalError),
            }
        }
        _ => {
            if let Some(h) = e.hasher.as_mut() {
                h.update(data);
            }
            if !data.is_empty() {
                let rc = ((*sys).provider_call)(
                    handle,
                    obj::PUT_STREAMED_WRITE,
                    data.as_ptr() as *mut u8,
                    data.len(),
                );
                if rc < 0 {
                    write_err = rc;
                }
                written = data.len() as u64;
            }
            Ok(())
        }
    };
    if let Err(err) = outcome {
        fail(s, i, err);
        return;
    }
    if write_err != 0 {
        fail(s, i, s3_errno(write_err, false));
        return;
    }
    let e = &mut s.ex[i];
    e.received += written;
    if e.received > e.declared {
        fail(s, i, S3Err::IncompleteBody);
        return;
    }
    e.credit_owed = e.credit_owed.saturating_add(data.len() as u32);
    if last {
        finish_put_body(s, i);
    }
}

/// The body has ended: check it whole, then commit.
unsafe fn finish_put_body(s: &mut State, i: usize) {
    let e = &mut s.ex[i];
    if e.received != e.declared {
        fail(s, i, S3Err::IncompleteBody);
        return;
    }
    match e.payload {
        Payload::Hashed(want) => {
            let got = e.hasher.take().map(|h| h.finalize());
            if got != Some(want) {
                fail(s, i, S3Err::XAmzContentSha256Mismatch);
                return;
            }
        }
        Payload::Chunked => {
            if !e.chunked.as_ref().map(S3Chunked::done).unwrap_or(false) {
                fail(s, i, S3Err::IncompleteBody);
                return;
            }
        }
        Payload::Unsigned => {}
    }
    let e = &mut s.ex[i];
    e.arg[..8].copy_from_slice(&(e.fence.as_mut_ptr() as u64).to_le_bytes());
    e.arg[8..10].copy_from_slice(&(WIRE_MAX_LEN as u16).to_le_bytes());
    e.arg_len = 10;
    e.phase = Phase::PutCommit;
    put_commit(s, i);
}

/// Commit the streamed put; asked again with the same request while the
/// provider has not decided. Acknowledged only at the fence it reports.
unsafe fn put_commit(s: &mut State, i: usize) -> bool {
    let e = &mut s.ex[i];
    match obj::write_answer(call(
        s.syscalls,
        e.handle,
        obj::PUT_STREAMED_COMMIT,
        e.arg.as_mut_ptr(),
        e.arg_len,
    )) {
        obj::WriteAnswer::Pending => false,
        obj::WriteAnswer::Decided(0) => {
            call(
                s.syscalls,
                s.ex[i].handle,
                obj::CLOSE,
                core::ptr::null_mut(),
                0,
            );
            s.ex[i].handle = -1;
            s.ex[i].phase = Phase::PutHead;
            true
        }
        obj::WriteAnswer::Decided(err) => {
            // A refused commit leaves the handle unwritable, still to close.
            call(
                s.syscalls,
                s.ex[i].handle,
                obj::CLOSE,
                core::ptr::null_mut(),
                0,
            );
            s.ex[i].handle = -1;
            fail(s, i, s3_errno(err, false));
            true
        }
    }
}

/// The committed object's entity tag, for the answer.
unsafe fn put_head(s: &mut State, i: usize) -> bool {
    match head_object(s, i) {
        Err(errno::EAGAIN) => false,
        Err(err) => {
            fail(s, i, s3_errno(err, false));
            true
        }
        Ok(()) => {
            let e = &s.ex[i];
            let mut hdr = [0u8; 512];
            let mut h = S3Out::new(&mut hdr);
            h.put(b"etag: ");
            s3_etag(&e.etag[..e.etag_len], &mut h);
            h.put(b"\r\nx-amz-request-id: ");
            h.put(&e.request_id);
            h.put(b"\r\n");
            fence_header(&e.fence, &mut h);
            let hl = h.len;
            if s.ex[i].op == S3Op::UploadPart {
                let slot = s.ex[i].upload_slot as usize;
                s.uploads[slot].touched = now_ms(s) / 1000;
            }
            stage_head(s, i, 200, b"application/xml", &hdr[..hl], b"", true);
            s.ex[i].phase = Phase::Answer;
            true
        }
    }
}

/// `x-fluxor-fence:` naming the fence the provider reported for a write.
fn fence_header(fence: &[u8; WIRE_MAX_LEN], h: &mut S3Out<'_>) {
    // Spans of one literal, not a table of slices, which the flat module
    // image could not relocate.
    const NAMES: &[u8] =
        b"volatilelocal-durablereplicated-durablecontent-hashedrevision-monotoneview-consistent";
    let (at, len): (usize, usize) = match Fence::decode(fence) {
        Some((Fence::Volatile, _)) => (0, 8),
        Some((Fence::LocalDurable { .. }, _)) => (8, 13),
        Some((Fence::ReplicatedDurable { .. }, _)) => (21, 18),
        Some((Fence::ContentHashed { .. }, _)) => (39, 14),
        Some((Fence::RevisionMonotone { .. }, _)) => (53, 17),
        Some((Fence::ViewConsistent { .. }, _)) => (70, 15),
        None => return,
    };
    let Some(name) = NAMES.get(at..at + len) else {
        return;
    };
    h.put(b"x-fluxor-fence: ");
    h.put(name);
    h.put(b"\r\n");
}

/// `HEAD` the exchange's object into its `size`/`mtime`/`etag`.
unsafe fn head_object(s: &mut State, i: usize) -> Result<(), i32> {
    let grant = s.creds[s.ex[i].cred as usize].grant;
    let e = &mut s.ex[i];
    let mut out = [0u8; 8 + 8 + 1 + 255 + 1 + 255];
    // The read's own fence: the exchange's `fence` keeps what a write
    // reported, which is what its answer names.
    let mut fence = [0u8; WIRE_MAX_LEN];
    let key = &e.name[..e.name_len];
    let mut arg = [0u8; NAME_MAX + 32];
    arg[..2].copy_from_slice(&(key.len() as u16).to_le_bytes());
    arg[2..2 + key.len()].copy_from_slice(key);
    let mut p = 2 + key.len();
    arg[p..p + 8].copy_from_slice(&(out.as_mut_ptr() as u64).to_le_bytes());
    arg[p + 8..p + 12].copy_from_slice(&(out.len() as u32).to_le_bytes());
    arg[p + 12..p + 20].copy_from_slice(&(fence.as_mut_ptr() as u64).to_le_bytes());
    arg[p + 20..p + 22].copy_from_slice(&(WIRE_MAX_LEN as u16).to_le_bytes());
    p += 22;
    let rc = call(s.syscalls, grant, obj::HEAD, arg.as_mut_ptr(), p);
    if rc < 0 {
        return Err(rc);
    }
    let Some((h, _ct, etag)) = obj::range::decode_head(&out[..rc as usize]) else {
        return Err(errno::ERROR);
    };
    let e = &mut s.ex[i];
    e.size = h.size;
    e.mtime = h.mtime;
    if etag.len() > ETAG_MAX {
        return Err(errno::ERROR);
    }
    e.etag_len = etag.len();
    e.etag[..e.etag_len].copy_from_slice(etag);
    Ok(())
}

// ── GET and HEAD ──────────────────────────────────────────────────────────

/// Longest `Range` value kept: a single `bytes=a-b` range of two `u64`s is
/// shorter, and anything longer is served whole, as `s3_range` would.
const READ_RANGE_MAX: usize = 64;
/// Longest `If-Match` / `If-None-Match` value kept.
const READ_COND_MAX: usize = 200;

/// The read conditions a GET or HEAD carries, kept in the exchange's `arg`
/// while the provider may answer `EAGAIN`:
/// `[range_len u8][range][if_match_len u8][if_match][if_none_len u8][if_none]`,
/// each length `0xFF` when the header is absent.
unsafe fn begin_read(s: &mut State, i: usize, headers: &[u8]) -> Result<(), S3Err> {
    let e = &mut s.ex[i];
    let range = sv4_header(headers, b"range").filter(|v| v.len() <= READ_RANGE_MAX);
    let mut p = keep_cond(&mut e.arg, 0, range, READ_RANGE_MAX)?;
    p = keep_cond(
        &mut e.arg,
        p,
        sv4_header(headers, b"if-match"),
        READ_COND_MAX,
    )?;
    p = keep_cond(
        &mut e.arg,
        p,
        sv4_header(headers, b"if-none-match"),
        READ_COND_MAX,
    )?;
    e.arg_len = p;
    e.phase = Phase::ReadHead;
    read_head(s, i);
    Ok(())
}

/// Keep one read condition at `arg[p..]`; the offset after it.
fn keep_cond(arg: &mut [u8], p: usize, v: Option<&[u8]>, max: usize) -> Result<usize, S3Err> {
    let Some(v) = v else {
        *arg.get_mut(p).ok_or(S3Err::InternalError)? = 0xFF;
        return Ok(p + 1);
    };
    if v.len() > max {
        return Err(S3Err::InvalidArgument);
    }
    let out = arg
        .get_mut(p..p + 1 + v.len())
        .ok_or(S3Err::InternalError)?;
    out[0] = v.len() as u8;
    out[1..].copy_from_slice(v);
    Ok(p + 1 + v.len())
}

/// Read condition `k` (0 range, 1 if-match, 2 if-none-match) kept by
/// `begin_read`.
fn read_cond(arg: &[u8], k: usize) -> Option<&[u8]> {
    let mut p = 0usize;
    for at in 0..3 {
        let len = *arg.get(p)?;
        let v = if len == 0xFF {
            None
        } else {
            arg.get(p + 1..p + 1 + len as usize)
        };
        if at == k {
            return v;
        }
        p += 1 + if len == 0xFF { 0 } else { len as usize };
    }
    None
}

/// Whether an `If-Match` / `If-None-Match` value names `etag`.
fn etag_matches(v: &[u8], etag: &[u8]) -> bool {
    v == b"*"
        || v.split(|&c| c == b',').any(|t| {
            let t = trim(t);
            let t = t.strip_prefix(b"\"").and_then(|t| t.strip_suffix(b"\"")).unwrap_or(t);
            t.len() == 2 * etag.len()
                && t.chunks(2).zip(etag).all(|(p, &b)| {
                    matches!((sv4_hexval(p[0]), sv4_hexval(p[1])), (Some(h), Some(l)) if (h << 4) | l == b)
                })
        })
}

/// The object's metadata, then the conditions and range it is read under.
/// Asked again while the provider answers `EAGAIN`.
unsafe fn read_head(s: &mut State, i: usize) -> bool {
    match head_object(s, i) {
        Ok(()) => {}
        Err(errno::EAGAIN) => return false,
        Err(rc) => {
            fail(s, i, s3_errno(rc, false));
            return true;
        }
    }
    let e = &s.ex[i];
    let size = e.size;
    let etag = &e.etag[..e.etag_len];
    let arg = &e.arg[..e.arg_len];
    if let Some(v) = read_cond(arg, 1) {
        if !etag_matches(v, etag) {
            fail(s, i, S3Err::PreconditionFailed);
            return true;
        }
    }
    let not_modified = read_cond(arg, 2).is_some_and(|v| etag_matches(v, etag));
    let (status, start, endb) = match s3_range(read_cond(arg, 0), size) {
        S3Range::Whole => (200u16, 0u64, size),
        S3Range::Part { start, end } => (206, start, end + 1),
        S3Range::Unsatisfiable => {
            fail(s, i, S3Err::InvalidRange);
            return true;
        }
    };
    let status = if not_modified { 304 } else { status };
    let head_only = s.ex[i].op == S3Op::HeadObject || status == 304 || endb == start;
    let e = &mut s.ex[i];
    e.offset = start;
    e.end = endb;
    e.part = status as u32;
    if head_only {
        stage_read_head(s, i, true);
        s.ex[i].phase = Phase::Answer;
        return true;
    }
    s.ex[i].phase = Phase::ReadOpen;
    read_open(s, i);
    true
}

/// Open the object for ranged reads, then answer the head. Asked again
/// while the provider answers `EAGAIN`.
unsafe fn read_open(s: &mut State, i: usize) -> bool {
    let grant = s.creds[s.ex[i].cred as usize].grant;
    let e = &mut s.ex[i];
    let h = call(s.syscalls, grant, obj::GET, e.name.as_mut_ptr(), e.name_len);
    if h == errno::EAGAIN {
        return false;
    }
    if h < 0 {
        fail(s, i, s3_errno(h, false));
        return true;
    }
    s.ex[i].handle = h;
    stage_read_head(s, i, false);
    s.ex[i].phase = Phase::GetBody;
    true
}

/// Stage a read's response HEAD from the exchange's object metadata, range
/// and status (`part`).
unsafe fn stage_read_head(s: &mut State, i: usize, last: bool) {
    let e = &s.ex[i];
    let status = e.part as u16;
    let (start, endb, size) = (e.offset, e.end, e.size);
    let mut hdr = [0u8; 768];
    let mut h = S3Out::new(&mut hdr);
    h.put(b"etag: ");
    s3_etag(&e.etag[..e.etag_len], &mut h);
    h.put(b"\r\nlast-modified: ");
    s3_http_date(e.mtime / 1_000_000_000, &mut h);
    h.put(b"\r\naccept-ranges: bytes\r\nx-amz-request-id: ");
    h.put(&e.request_id);
    h.put(b"\r\n");
    if status != 304 {
        h.put(b"content-length: ");
        h.dec(endb - start);
        h.put(b"\r\n");
        if status == 206 {
            h.put(b"content-range: bytes ");
            h.dec(start);
            h.put(b"-");
            h.dec(endb.saturating_sub(1));
            h.put(b"/");
            h.dec(size);
            h.put(b"\r\n");
        }
    }
    let hl = h.len;
    stage_head(
        s,
        i,
        status,
        b"application/octet-stream",
        &hdr[..hl],
        b"",
        last,
    );
}

fn trim(v: &[u8]) -> &[u8] {
    let a = v.iter().position(|&c| c != b' ').unwrap_or(v.len());
    let b = v.iter().rposition(|&c| c != b' ').map_or(a, |e| e + 1);
    &v[a..b]
}

/// One ranged read into a BODY record, as far as `http`'s credit allows.
unsafe fn get_body(s: &mut State, i: usize) -> bool {
    let e = &mut s.ex[i];
    let left = e.end - e.offset;
    let n = (left.min(e.resp_credit as u64).min(BODY_MAX as u64)) as usize;
    if n == 0 && left > 0 {
        return false;
    }
    let out = core::slice::from_raw_parts_mut(e.out, RECORD_MAX);
    let data_at = exchange::HDR;
    let mut got = 0usize;
    while got < n {
        let mut arg = [0u8; 20];
        arg[..8].copy_from_slice(&(e.offset + got as u64).to_le_bytes());
        arg[8..12].copy_from_slice(&((n - got) as u32).to_le_bytes());
        arg[12..20].copy_from_slice(&(out.as_mut_ptr().add(data_at + got) as u64).to_le_bytes());
        let rc = call(
            s.syscalls,
            e.handle,
            obj::RANGE_GET,
            arg.as_mut_ptr(),
            arg.len(),
        );
        if rc == errno::EAGAIN {
            break;
        }
        if rc <= 0 {
            // The object ended before its declared length, or the read
            // failed: the peer's response cannot be completed.
            abort_out(s, i);
            return true;
        }
        got += rc as usize;
    }
    if got == 0 && left > 0 {
        return false;
    }
    let e = &mut s.ex[i];
    let last = e.offset + got as u64 == e.end;
    let flags = if last { 0 } else { flag::MORE };
    let Some(len) = exchange::seal_body(&e.id, flags, got, out) else {
        abort_out(s, i);
        return true;
    };
    e.offset += got as u64;
    e.resp_credit -= got as u32;
    e.out_len = len;
    e.out_state = Out::Pending;
    e.out_final = last;
    if last {
        call(s.syscalls, e.handle, obj::CLOSE, core::ptr::null_mut(), 0);
        s.ex[i].handle = -1;
        s.ex[i].phase = Phase::Answer;
    }
    true
}

// ── DELETE ────────────────────────────────────────────────────────────────

unsafe fn delete_step(s: &mut State, i: usize) -> bool {
    let grant = s.creds[s.ex[i].cred as usize].grant;
    let e = &mut s.ex[i];
    if e.arg_len == 0 {
        let key = &e.name[..e.name_len];
        let mut fence = e.fence;
        let n = delete_arg(&mut e.arg, key, &mut fence).unwrap_or(0);
        // The fence pointer must name the exchange's own buffer, which stays
        // put while the provider may answer on a later ask.
        let p = 2 + e.name_len + 2;
        e.arg[p..p + 8].copy_from_slice(&(e.fence.as_mut_ptr() as u64).to_le_bytes());
        e.arg_len = n;
    }
    match obj::write_answer(call(
        s.syscalls,
        grant,
        obj::DELETE,
        s.ex[i].arg.as_mut_ptr(),
        s.ex[i].arg_len,
    )) {
        obj::WriteAnswer::Pending => false,
        obj::WriteAnswer::Decided(rc) if rc == 0 || rc == errno::ENXIO || rc == errno::ENOENT => {
            // S3 answers a delete of a missing key as done.
            let e = &s.ex[i];
            let mut hdr = [0u8; 256];
            let mut h = S3Out::new(&mut hdr);
            h.put(b"x-amz-request-id: ");
            h.put(&e.request_id);
            h.put(b"\r\n");
            fence_header(&e.fence, &mut h);
            let hl = h.len;
            stage_head(s, i, 204, b"", &hdr[..hl], b"", true);
            s.ex[i].phase = Phase::Answer;
            true
        }
        obj::WriteAnswer::Decided(err) => {
            fail(s, i, s3_errno(err, false));
            true
        }
    }
}

// ── Buckets ───────────────────────────────────────────────────────────────

unsafe fn list_buckets(s: &mut State, i: usize) -> Result<(), S3Err> {
    let c = s.creds[s.ex[i].cred as usize];
    let mut body = [0u8; 1024];
    let mut o = S3Out::new(&mut body);
    o.put(S3_XML_DECL);
    o.put(b"<ListAllMyBucketsResult");
    o.put(S3_XMLNS);
    o.put(b"><Owner>");
    o.elem(b"ID", c.ak());
    o.elem(b"DisplayName", c.ak());
    o.put(b"</Owner><Buckets><Bucket>");
    o.elem(b"Name", c.bucket());
    o.put(b"<CreationDate>");
    s3_iso_date(0, &mut o);
    o.put(b"</CreationDate></Bucket></Buckets></ListAllMyBucketsResult>");
    let len = o.len;
    if len as u32 > s.ex[i].resp_credit {
        return Err(S3Err::InternalError);
    }
    stage_head(s, i, 200, b"application/xml", b"", &body[..len], true);
    s.ex[i].phase = Phase::Answer;
    Ok(())
}

/// Whether the key's grant reaches the bucket, asked of the provider: a
/// one-entry listing of the bucket's objects.
unsafe fn bucket_probe(s: &mut State, i: usize) -> bool {
    let grant = s.creds[s.ex[i].cred as usize].grant;
    let name_len = s.ex[i].name_len;
    let mut prefix = [0u8; NAME_MAX];
    prefix[..name_len].copy_from_slice(&s.ex[i].name[..name_len]);
    match list_page(s, grant, &prefix[..name_len], &[], 1, LIST_PAGE_BUF) {
        Err(errno::EAGAIN) => false,
        Err(err) => {
            fail(
                s,
                i,
                if err == errno::EACCES {
                    S3Err::AccessDenied
                } else {
                    s3_errno(err, false)
                },
            );
            true
        }
        Ok(_) => {
            let mut body = [0u8; 256];
            let mut o = S3Out::new(&mut body);
            if s.ex[i].op == S3Op::GetBucketLocation {
                o.put(S3_XML_DECL);
                o.put(b"<LocationConstraint");
                o.put(S3_XMLNS);
                o.put(b">");
                let rl = s.region_len;
                let mut region = [0u8; 32];
                region[..rl].copy_from_slice(&s.region[..rl]);
                o.xml_text(&region[..rl]);
                o.put(b"</LocationConstraint>");
            }
            let len = o.len;
            if len > 0 {
                stage_head(s, i, 200, b"application/xml", b"", &body[..len], true);
            } else {
                stage_head(s, i, 200, b"", b"", &body[..len], true);
            }
            s.ex[i].phase = Phase::Answer;
            true
        }
    }
}

// ── Listing ───────────────────────────────────────────────────────────────

unsafe fn begin_list(
    s: &mut State,
    i: usize,
    bucket: &[u8],
    query: &[u8],
    op: S3Op,
) -> Result<(), S3Err> {
    let mut l = LIST_EMPTY;
    l.v2 = op == S3Op::ListObjectsV2;
    l.url = sv4_query_param(query, b"encoding-type") == Some(b"url");
    let mut tmp = [0u8; NAME_MAX];
    let prefix_raw = sv4_query_param(query, b"prefix").unwrap_or(b"");
    let pl = sv4_decode(prefix_raw, &mut tmp).ok_or(S3Err::InvalidArgument)?;
    let n = s3_list_prefix(bucket, &tmp[..pl], &mut l.prefix)?;
    l.prefix_len = n as u16;
    let delim_raw = sv4_query_param(query, b"delimiter").unwrap_or(b"");
    let dl = sv4_decode(delim_raw, &mut l.delim).ok_or(S3Err::InvalidArgument)?;
    l.delim_len = dl as u8;
    l.max = match sv4_query_param(query, b"max-keys") {
        None => obj::LIST_PAGE_MAX,
        Some(v) => {
            let m = sv4_digits(v).ok_or(S3Err::InvalidArgument)?;
            if m > obj::LIST_PAGE_MAX as u64 {
                return Err(S3Err::InvalidArgument);
            }
            m as u16
        }
    };
    // Where the listing resumes: a continuation token this server issued, or
    // a key the client names (`start-after`, `marker`), skipped up to.
    let token = if l.v2 {
        sv4_query_param(query, b"continuation-token")
    } else {
        None
    };
    if let Some(t) = token {
        let mut dec = [0u8; 2 * (2 * NAME_MAX + 1)];
        let tl = sv4_decode(t, &mut dec).ok_or(S3Err::InvalidArgument)?;
        let mut cur = [0u8; NAME_MAX];
        let mut cp = [0u8; NAME_MAX];
        let (c, p) =
            s3_token_decode(&dec[..tl], &mut cur, &mut cp).ok_or(S3Err::InvalidArgument)?;
        l.cursor[..c.len()].copy_from_slice(c);
        l.cursor_len = c.len() as u16;
        l.last_cp[..p.len()].copy_from_slice(p);
        l.last_cp_len = p.len() as u16;
    }
    let after_raw = if l.v2 {
        sv4_query_param(query, b"start-after")
    } else {
        sv4_query_param(query, b"marker")
    };
    if let Some(a) = after_raw {
        let al = sv4_decode(a, &mut tmp).ok_or(S3Err::InvalidArgument)?;
        let n = s3_join_bytes(&mut l.after, &[bucket, S3_OBJECTS, &tmp[..al]])
            .ok_or(S3Err::KeyTooLong)?;
        l.after_len = n as u16;
    }
    l.page = heap_alloc(&*s.syscalls, LIST_PAGE_BUF as u32);
    if l.page.is_null() {
        return Err(S3Err::SlowDown);
    }
    s.ex[i].list = l;
    s.ex[i].phase = Phase::List;
    Ok(())
}

/// One `LIST` page rendered into the listing document, or the rendered
/// document sent as far as credit allows.
unsafe fn list_step(s: &mut State, i: usize) -> bool {
    // Send what is rendered first.
    if s.ex[i].list.pending > 0 {
        return list_send(s, i);
    }
    if s.ex[i].list.done {
        return false;
    }
    let grant = s.creds[s.ex[i].cred as usize].grant;
    let l = s.ex[i].list;
    let budget = l.max.saturating_sub(l.emitted);
    if budget == 0 || l.max == 0 {
        s.ex[i].list.done = true;
        render_list_tail(s, i, l.cursor_len > 0);
        return true;
    }
    let page = list_page(
        s,
        grant,
        &l.prefix[..l.prefix_len as usize],
        &l.cursor[..l.cursor_len as usize],
        budget,
        LIST_RENDER_CAP,
    );
    let len = match page {
        Err(errno::EAGAIN) => return false,
        Err(err) => {
            fail(s, i, s3_errno(err, false));
            return true;
        }
        Ok((len, _)) => len,
    };
    // Render into the exchange's listing buffer: the head of the document
    // first, then the page's entries.
    let doc = core::slice::from_raw_parts_mut(s.ex[i].list.page, LIST_PAGE_BUF);
    let page_bytes: &[u8] = core::slice::from_raw_parts(s.page.as_ptr(), len);
    let Some(p) = obj::list::decode_page(page_bytes) else {
        fail(s, i, S3Err::InternalError);
        return true;
    };
    let mut o = S3Out::new(doc);
    let bucket_len = s.ex[i].bucket_len;
    let mut bucket = [0u8; S3_BUCKET_MAX];
    bucket[..bucket_len].copy_from_slice(&s.ex[i].list.prefix[..bucket_len]);
    let bucket = &bucket[..bucket_len];
    if !s.ex[i].list.opened {
        render_list_head(s, i, &mut o, bucket);
        s.ex[i].list.opened = true;
    }
    let l = &mut s.ex[i].list;
    let obj_prefix_len = bucket_len + S3_OBJECTS.len();
    let user_prefix = &l.prefix[obj_prefix_len..l.prefix_len as usize];
    let delim = &l.delim[..l.delim_len as usize];
    for e in p.entries() {
        if l.after_len > 0 && e.key <= &l.after[..l.after_len as usize] {
            continue;
        }
        let Some(key) = s3_key_of(e.key, bucket) else {
            continue;
        };
        if let Some(cp) = s3_common_prefix(key, user_prefix, delim) {
            if cp == &l.last_cp[..l.last_cp_len as usize] {
                continue;
            }
            l.last_cp[..cp.len()].copy_from_slice(cp);
            l.last_cp_len = cp.len() as u16;
            o.put(b"<CommonPrefixes><Prefix>");
            if l.url {
                o.url_text(cp);
            } else {
                o.xml_text(cp);
            }
            o.put(b"</Prefix></CommonPrefixes>");
        } else {
            o.put(b"<Contents><Key>");
            if l.url {
                o.url_text(key);
            } else {
                o.xml_text(key);
            }
            o.put(b"</Key><LastModified>");
            s3_iso_date(e.mtime / 1_000_000_000, &mut o);
            o.put(b"</LastModified><ETag>&quot;");
            o.hex(e.etag);
            o.put(b"&quot;</ETag>");
            o.elem_dec(b"Size", e.size);
            o.put(b"<StorageClass>STANDARD</StorageClass></Contents>");
        }
        l.emitted += 1;
    }
    let cursor = p.cursor();
    l.cursor[..cursor.len()].copy_from_slice(cursor);
    l.cursor_len = cursor.len() as u16;
    let last = p.is_last();
    let full = l.emitted >= l.max;
    if o.over {
        fail(s, i, S3Err::InternalError);
        return true;
    }
    s.ex[i].list.pending = o.len as u16;
    if last || full {
        s.ex[i].list.done = true;
        render_list_tail(s, i, !last);
    }
    true
}

unsafe fn render_list_head(s: &State, i: usize, o: &mut S3Out<'_>, bucket: &[u8]) {
    let l = &s.ex[i].list;
    let obj_prefix_len = bucket.len() + S3_OBJECTS.len();
    o.put(S3_XML_DECL);
    o.put(b"<ListBucketResult");
    o.put(S3_XMLNS);
    o.put(b">");
    o.elem(b"Name", bucket);
    o.put(b"<Prefix>");
    let up = &l.prefix[obj_prefix_len..l.prefix_len as usize];
    if l.url {
        o.url_text(up);
    } else {
        o.xml_text(up);
    }
    o.put(b"</Prefix>");
    if l.delim_len > 0 {
        o.elem(b"Delimiter", &l.delim[..l.delim_len as usize]);
    }
    o.elem_dec(b"MaxKeys", l.max as u64);
    if l.url {
        o.put(b"<EncodingType>url</EncodingType>");
    }
}

/// Close the listing document: truncation and the token that resumes it.
unsafe fn render_list_tail(s: &mut State, i: usize, truncated: bool) {
    let l = s.ex[i].list;
    let at = l.pending as usize;
    let doc = core::slice::from_raw_parts_mut(l.page.add(at), LIST_PAGE_BUF - at);
    let mut o = S3Out::new(doc);
    if !l.opened {
        let bucket_len = s.ex[i].bucket_len;
        let mut bucket = [0u8; S3_BUCKET_MAX];
        bucket[..bucket_len].copy_from_slice(&l.prefix[..bucket_len]);
        render_list_head(s, i, &mut o, &bucket[..bucket_len]);
    }
    if l.v2 {
        o.elem_dec(b"KeyCount", l.emitted as u64);
    }
    if truncated {
        o.put(b"<IsTruncated>true</IsTruncated>");
    } else {
        o.put(b"<IsTruncated>false</IsTruncated>");
    }
    if truncated {
        if l.v2 {
            o.put(b"<NextContinuationToken>");
            s3_token_encode(
                &l.cursor[..l.cursor_len as usize],
                &l.last_cp[..l.last_cp_len as usize],
                &mut o,
            );
            o.put(b"</NextContinuationToken>");
        } else if l.cursor_len > 0 {
            let bucket_len = s.ex[i].bucket_len + S3_OBJECTS.len();
            let next = &l.cursor[bucket_len.min(l.cursor_len as usize)..l.cursor_len as usize];
            o.elem(b"NextMarker", next);
        }
    }
    o.put(b"</ListBucketResult>");
    let n = o.len;
    s.ex[i].list.pending = (at + n) as u16;
    s.ex[i].list.opened = true;
}

/// Send the rendered listing, head first, as credit allows.
unsafe fn list_send(s: &mut State, i: usize) -> bool {
    let pending = s.ex[i].list.pending as usize;
    let done = s.ex[i].list.done;
    let credit = s.ex[i].resp_credit as usize;
    let room = BODY_MAX - 64;
    let n = pending.min(credit).min(room);
    if n == 0 {
        return false;
    }
    let mut chunk = [0u8; BODY_MAX];
    chunk[..n].copy_from_slice(core::slice::from_raw_parts(s.ex[i].list.page, n));
    let rest = pending - n;
    let page = s.ex[i].list.page;
    core::ptr::copy(page.add(n), page, rest);
    s.ex[i].list.pending = rest as u16;
    let last = done && rest == 0;
    if !s.ex[i].head_sent {
        let mut hdr = [0u8; 64];
        let mut h = S3Out::new(&mut hdr);
        h.put(b"x-amz-request-id: ");
        h.put(&s.ex[i].request_id);
        h.put(b"\r\n");
        let hl = h.len;
        stage_head(s, i, 200, b"application/xml", &hdr[..hl], &chunk[..n], last);
    } else {
        stage_body(s, i, &chunk[..n], last);
    }
    if last {
        s.ex[i].phase = Phase::Answer;
    }
    true
}

// ── Multipart ─────────────────────────────────────────────────────────────

unsafe fn begin_create_upload(s: &mut State, i: usize) -> Result<(), S3Err> {
    let Some(slot) = s.uploads.iter().position(|u| !u.used) else {
        return Err(S3Err::SlowDown);
    };
    let mut raw = [0u8; 16];
    dev_csprng_fill(&*s.syscalls, raw.as_mut_ptr(), raw.len());
    let mut id = [0u8; S3_UPLOAD_ID_LEN];
    sv4_hex(&raw, &mut id);
    let e = &mut s.ex[i];
    let u = &mut s.uploads[slot];
    *u = UPLOAD_EMPTY;
    u.used = true;
    u.busy = true;
    u.id = id;
    u.name[..e.name_len].copy_from_slice(&e.name[..e.name_len]);
    u.name_len = e.name_len as u16;
    u.bucket_len = e.bucket_len as u8;
    u.cred = e.cred;
    e.upload = id;
    e.upload_slot = slot as i16;
    // The marker records the upload in the store, so staging left by a
    // restart is found and reclaimed.
    let bucket_len = e.bucket_len;
    let mut bucket = [0u8; S3_BUCKET_MAX];
    bucket[..bucket_len].copy_from_slice(&e.name[..bucket_len]);
    let mut marker = [0u8; NAME_MAX];
    let ml = s3_upload_name(&bucket[..bucket_len], &id, 0, &mut marker).ok_or(S3Err::KeyTooLong)?;
    // [key_len][key][ct_len=0][body_ptr][body_len][precondition ABSENT][0][fence ptr][cap]
    let body_ptr = e.name.as_ptr() as u64;
    let body_len = e.name_len as u64;
    let a = &mut e.arg;
    let mut p = 0usize;
    a[p..p + 2].copy_from_slice(&(ml as u16).to_le_bytes());
    p += 2;
    a[p..p + ml].copy_from_slice(&marker[..ml]);
    p += ml;
    a[p] = 0;
    p += 1;
    a[p..p + 8].copy_from_slice(&body_ptr.to_le_bytes());
    a[p + 8..p + 16].copy_from_slice(&body_len.to_le_bytes());
    p += 16;
    a[p] = obj::precondition::ABSENT;
    a[p + 1] = 0;
    p += 2;
    a[p..p + 8].copy_from_slice(&(e.fence.as_mut_ptr() as u64).to_le_bytes());
    a[p + 8..p + 10].copy_from_slice(&(WIRE_MAX_LEN as u16).to_le_bytes());
    p += 10;
    e.arg_len = p;
    e.phase = Phase::UploadCreate;
    Ok(())
}

unsafe fn upload_create(s: &mut State, i: usize) -> bool {
    let grant = s.creds[s.ex[i].cred as usize].grant;
    match obj::write_answer(call(
        s.syscalls,
        grant,
        obj::PUT,
        s.ex[i].arg.as_mut_ptr(),
        s.ex[i].arg_len,
    )) {
        obj::WriteAnswer::Pending => false,
        obj::WriteAnswer::Decided(0) => {
            let slot = s.ex[i].upload_slot as usize;
            s.uploads[slot].busy = false;
            s.uploads[slot].touched = now_ms(s) / 1000;
            s.ex[i].upload_slot = -1;
            let e = &s.ex[i];
            let bucket_len = e.bucket_len;
            let mut body = [0u8; 1024];
            let mut o = S3Out::new(&mut body);
            o.put(S3_XML_DECL);
            o.put(b"<InitiateMultipartUploadResult");
            o.put(S3_XMLNS);
            o.put(b">");
            o.elem(b"Bucket", &e.name[..bucket_len]);
            o.elem(
                b"Key",
                s3_key_of(&e.name[..e.name_len], &e.name[..bucket_len]).unwrap_or(b""),
            );
            o.elem(b"UploadId", &e.upload);
            o.put(b"</InitiateMultipartUploadResult>");
            let len = o.len;
            stage_head(s, i, 200, b"application/xml", b"", &body[..len], true);
            s.ex[i].phase = Phase::Answer;
            true
        }
        obj::WriteAnswer::Decided(err) => {
            let slot = s.ex[i].upload_slot as usize;
            s.uploads[slot] = UPLOAD_EMPTY;
            s.ex[i].upload_slot = -1;
            fail(s, i, s3_errno(err, false));
            true
        }
    }
}

unsafe fn begin_complete(s: &mut State, i: usize) -> Result<(), S3Err> {
    let slot = s.ex[i].upload_slot as usize;
    if s.completions == MAX_COMPLETIONS {
        return Err(S3Err::SlowDown);
    }
    let parts = heap_alloc(&*s.syscalls, S3_PART_NUMBER_MAX * 4) as *mut u32;
    if parts.is_null() {
        return Err(S3Err::SlowDown);
    }
    let etags = heap_alloc(&*s.syscalls, S3_PART_NUMBER_MAX * PART_ETAG_STRIDE as u32);
    if etags.is_null() {
        heap_free(&*s.syscalls, parts as *mut u8);
        return Err(S3Err::SlowDown);
    }
    s.completions += 1;
    s.uploads[slot].busy = true;
    let e = &mut s.ex[i];
    e.parts = parts;
    e.part_etags = etags;
    e.parts_len = 0;
    e.parts_reader = Some(S3PartsReader::new());
    e.hasher = match e.payload {
        Payload::Hashed(_) => Some(Sha256::new()),
        _ => None,
    };
    if e.payload == Payload::Chunked {
        return Err(S3Err::NotImplemented);
    }
    e.phase = Phase::CompleteParts;
    if e.body_open {
        e.credit_owed = BODY_WINDOW;
    } else {
        return Err(S3Err::MalformedXml);
    }
    Ok(())
}

/// Part-list bytes of a completion body.
unsafe fn complete_data(s: &mut State, i: usize, data: &[u8], last: bool) {
    let e = &mut s.ex[i];
    if let Some(h) = e.hasher.as_mut() {
        h.update(data);
    }
    let parts = e.parts;
    let etags = e.part_etags;
    let mut count = e.parts_len;
    let mut bad = e.parts_bad;
    if let Some(r) = e.parts_reader.as_mut() {
        let res = r.feed(data, |p| {
            if count >= S3_PART_NUMBER_MAX {
                return;
            }
            // The tag as listed, decoded to the bytes the provider answers.
            let at = etags.add(count as usize * PART_ETAG_STRIDE);
            match part_etag(&p.etag[..p.etag_len as usize], at.add(1)) {
                Some(n) => *at = n as u8,
                None => {
                    if bad.is_none() {
                        bad = Some(if p.etag_len == 0 {
                            S3Err::MalformedXml
                        } else {
                            S3Err::InvalidPart
                        });
                    }
                    *at = 0;
                }
            }
            *parts.add(count as usize) = p.number;
            count += 1;
        });
        match res {
            Ok(()) => {}
            Err(S3PartsErr::Order) => bad = Some(S3Err::InvalidPartOrder),
            Err(_) => bad = Some(S3Err::MalformedXml),
        }
    }
    e.parts_len = count;
    e.parts_bad = bad;
    e.credit_owed = e.credit_owed.saturating_add(data.len() as u32);
    if !last {
        return;
    }
    if let Payload::Hashed(want) = e.payload {
        if e.hasher.take().map(|h| h.finalize()) != Some(want) {
            fail(s, i, S3Err::XAmzContentSha256Mismatch);
            return;
        }
    }
    if let Some(err) = s.ex[i].parts_bad {
        fail(s, i, err);
        return;
    }
    if s.ex[i].parts_len == 0 {
        fail(s, i, S3Err::MalformedXml);
        return;
    }
    s.ex[i].part_at = 0;
    s.ex[i].phase = Phase::CompleteCheck;
}

/// Decode a listed part's hex entity tag into the `ETAG_MAX` bytes at `out`;
/// its length, or `None` for one that is empty, not hex, or too long to be
/// any tag a provider answers.
unsafe fn part_etag(hex: &[u8], out: *mut u8) -> Option<usize> {
    if hex.is_empty() || !hex.len().is_multiple_of(2) || hex.len() > 2 * ETAG_MAX {
        return None;
    }
    for k in 0..hex.len() / 2 {
        let (h, l) = (sv4_hexval(hex[2 * k])?, sv4_hexval(hex[2 * k + 1])?);
        *out.add(k) = (h << 4) | l;
    }
    Some(hex.len() / 2)
}

/// The staging name of listed part `k` into the exchange's `name`.
unsafe fn part_name(s: &mut State, i: usize, k: u32) -> bool {
    let e = &mut s.ex[i];
    let number = *e.parts.add(k as usize);
    let slot = e.upload_slot as usize;
    let u = &s.uploads[slot];
    let bucket = &u.name[..u.bucket_len as usize];
    match s3_upload_name(bucket, &u.id, number, &mut e.name) {
        Some(n) => {
            e.name_len = n;
            true
        }
        None => false,
    }
}

/// Check each listed part exists and, all but the last, meets the minimum.
unsafe fn complete_check(s: &mut State, i: usize) -> bool {
    let k = s.ex[i].part_at;
    if k == s.ex[i].parts_len {
        return complete_open(s, i);
    }
    if !part_name(s, i, k) {
        fail(s, i, S3Err::InvalidPart);
        return true;
    }
    match head_object(s, i) {
        Err(errno::EAGAIN) => false,
        Err(_) => {
            fail(s, i, S3Err::InvalidPart);
            true
        }
        Ok(()) => {
            let e = &s.ex[i];
            let listed = e.part_etags.add(k as usize * PART_ETAG_STRIDE);
            let listed = core::slice::from_raw_parts(listed.add(1), *listed as usize);
            if listed != &e.etag[..e.etag_len] {
                fail(s, i, S3Err::InvalidPart);
                return true;
            }
            let last = k + 1 == s.ex[i].parts_len;
            if !last && s.ex[i].size < s.part_min {
                fail(s, i, S3Err::EntityTooSmall);
                return true;
            }
            s.ex[i].received = s.ex[i].received.saturating_add(s.ex[i].size);
            s.ex[i].part_at += 1;
            true
        }
    }
}

/// Open the final object's streamed put and answer the head, so the long
/// copy that follows is kept alive with whitespace as S3 does.
unsafe fn complete_open(s: &mut State, i: usize) -> bool {
    if s.ex[i].received > s.max_object {
        fail(s, i, S3Err::EntityTooLarge);
        return true;
    }
    let slot = s.ex[i].upload_slot as usize;
    let u = s.uploads[slot];
    let key = &u.name[..u.name_len as usize];
    let mut arg = [0u8; NAME_MAX + 32];
    let Some(p) = encode_put_open(
        &mut arg,
        key,
        &[],
        s.ex[i].received,
        obj::precondition::ANY,
        &[],
    ) else {
        fail(s, i, S3Err::KeyTooLong);
        return true;
    };
    let grant = s.creds[s.ex[i].cred as usize].grant;
    let h = call(
        s.syscalls,
        grant,
        obj::PUT_STREAMED_OPEN,
        arg.as_mut_ptr(),
        p,
    );
    if h < 0 {
        fail(s, i, s3_errno(h, false));
        return true;
    }
    s.ex[i].handle = h;
    s.ex[i].part_at = 0;
    s.ex[i].offset = 0;
    s.ex[i].end = 0;
    s.ex[i].keepalive_ms = now_ms(s);
    // The open handle on a part being copied is held beside the put.
    s.ex[i].size = 0;
    s.ex[i].etag_len = 0;
    let mut hdr = [0u8; 64];
    let mut h2 = S3Out::new(&mut hdr);
    h2.put(b"x-amz-request-id: ");
    h2.put(&s.ex[i].request_id);
    h2.put(b"\r\n");
    let hl = h2.len;
    // The declaration opens the document when the credit holds it; the
    // result reads the same without it.
    if s.ex[i].resp_credit as usize >= S3_XML_DECL.len() {
        stage_head(
            s,
            i,
            200,
            b"application/xml",
            &hdr[..hl],
            S3_XML_DECL,
            false,
        );
    } else {
        stage_head(s, i, 200, b"application/xml", &hdr[..hl], b"", false);
    }
    s.ex[i].phase = Phase::CompleteCopy;
    s.ex[i].mtime = u64::MAX;
    true
}

/// Copy one record's worth of the current part into the final object.
unsafe fn complete_copy(s: &mut State, i: usize) -> bool {
    // Whitespace keeps the response alive while the copy runs.
    let now = now_ms(s);
    if now.saturating_sub(s.ex[i].keepalive_ms) >= KEEPALIVE_MS && s.ex[i].resp_credit > 0 {
        s.ex[i].keepalive_ms = now;
        stage_body(s, i, b" ", false);
        return true;
    }
    let k = s.ex[i].part_at;
    if k == s.ex[i].parts_len {
        let e = &mut s.ex[i];
        e.arg[..8].copy_from_slice(&(e.fence.as_mut_ptr() as u64).to_le_bytes());
        e.arg[8..10].copy_from_slice(&(WIRE_MAX_LEN as u16).to_le_bytes());
        e.arg_len = 10;
        e.phase = Phase::CompleteCommit;
        return true;
    }
    // `mtime` holds the open part's read handle; `u64::MAX` when none.
    if s.ex[i].mtime == u64::MAX {
        if !part_name(s, i, k) {
            complete_fail(s, i, S3Err::InvalidPart);
            return true;
        }
        let grant = s.creds[s.ex[i].cred as usize].grant;
        let e = &mut s.ex[i];
        let h = call(s.syscalls, grant, obj::GET, e.name.as_mut_ptr(), e.name_len);
        if h == errno::EAGAIN {
            return false;
        }
        if h < 0 {
            complete_fail(s, i, S3Err::InvalidPart);
            return true;
        }
        s.ex[i].mtime = h as u64;
        s.ex[i].offset = 0;
    }
    let rh = s.ex[i].mtime as i32;
    let mut buf = [0u8; BODY_MAX];
    let mut arg = [0u8; 20];
    arg[..8].copy_from_slice(&s.ex[i].offset.to_le_bytes());
    arg[8..12].copy_from_slice(&(buf.len() as u32).to_le_bytes());
    arg[12..20].copy_from_slice(&(buf.as_mut_ptr() as u64).to_le_bytes());
    let n = call(s.syscalls, rh, obj::RANGE_GET, arg.as_mut_ptr(), arg.len());
    if n == errno::EAGAIN {
        return false;
    }
    if n < 0 {
        complete_fail(s, i, S3Err::InternalError);
        return true;
    }
    if n == 0 {
        call(s.syscalls, rh, obj::CLOSE, core::ptr::null_mut(), 0);
        s.ex[i].mtime = u64::MAX;
        s.ex[i].part_at += 1;
        return true;
    }
    let rc = call(
        s.syscalls,
        s.ex[i].handle,
        obj::PUT_STREAMED_WRITE,
        buf.as_mut_ptr(),
        n as usize,
    );
    if rc < 0 {
        call(s.syscalls, rh, obj::CLOSE, core::ptr::null_mut(), 0);
        s.ex[i].mtime = u64::MAX;
        complete_fail(s, i, s3_errno(rc, false));
        return true;
    }
    s.ex[i].offset += n as u64;
    true
}

/// A completion that failed after its 200 head went out: the error is a
/// document in the body, as S3 sends it.
unsafe fn complete_fail(s: &mut State, i: usize, err: S3Err) {
    if s.ex[i].mtime != u64::MAX {
        call(
            s.syscalls,
            s.ex[i].mtime as i32,
            obj::CLOSE,
            core::ptr::null_mut(),
            0,
        );
        s.ex[i].mtime = u64::MAX;
    }
    release_handles(s, i);
    if let Some(u) = usize::try_from(s.ex[i].upload_slot)
        .ok()
        .and_then(|k| s.uploads.get_mut(k))
    {
        u.busy = false;
    }
    let mut body = [0u8; 512];
    let mut o = S3Out::new(&mut body);
    o.put(b"<Error>");
    o.elem(b"Code", err.code());
    o.elem(b"Message", err.code());
    o.elem(b"RequestId", &s.ex[i].request_id);
    o.put(b"</Error>");
    let len = o.len.min(s.ex[i].resp_credit as usize);
    stage_body(s, i, &body[..len], true);
    s.ex[i].phase = Phase::Answer;
}

unsafe fn complete_commit(s: &mut State, i: usize) -> bool {
    let e = &mut s.ex[i];
    match obj::write_answer(call(
        s.syscalls,
        e.handle,
        obj::PUT_STREAMED_COMMIT,
        e.arg.as_mut_ptr(),
        e.arg_len,
    )) {
        obj::WriteAnswer::Pending => false,
        obj::WriteAnswer::Decided(0) => {
            call(
                s.syscalls,
                s.ex[i].handle,
                obj::CLOSE,
                core::ptr::null_mut(),
                0,
            );
            s.ex[i].handle = -1;
            // The final object's tag, then the staging is reaped.
            let slot = s.ex[i].upload_slot as usize;
            let u = s.uploads[slot];
            let e = &mut s.ex[i];
            e.name[..u.name_len as usize].copy_from_slice(&u.name[..u.name_len as usize]);
            e.name_len = u.name_len as usize;
            if head_object(s, i).is_err() {
                s.ex[i].etag_len = 0;
            }
            reap(s, slot);
            s.ex[i].upload_slot = -1;
            s.ex[i].phase = Phase::CompleteResult;
            complete_result(s, i);
            true
        }
        obj::WriteAnswer::Decided(err) => {
            call(
                s.syscalls,
                s.ex[i].handle,
                obj::CLOSE,
                core::ptr::null_mut(),
                0,
            );
            s.ex[i].handle = -1;
            complete_fail(s, i, s3_errno(err, false));
            true
        }
    }
}

/// The completed object's result document, once `http`'s credit holds it
/// whole. The object is committed by now; only the answer waits.
unsafe fn complete_result(s: &mut State, i: usize) -> bool {
    let e = &s.ex[i];
    let bucket_len = e.bucket_len;
    let mut body = [0u8; 1024];
    let mut o = S3Out::new(&mut body);
    o.put(b"<CompleteMultipartUploadResult");
    o.put(S3_XMLNS);
    o.put(b">");
    o.elem(b"Bucket", &e.name[..bucket_len]);
    o.elem(
        b"Key",
        s3_key_of(&e.name[..e.name_len], &e.name[..bucket_len]).unwrap_or(b""),
    );
    o.put(b"<ETag>&quot;");
    o.hex(&e.etag[..e.etag_len]);
    o.put(b"&quot;</ETag></CompleteMultipartUploadResult>");
    let len = o.len;
    if len as u32 > e.resp_credit {
        return false;
    }
    stage_body(s, i, &body[..len], true);
    s.ex[i].phase = Phase::Answer;
    true
}

/// Abort an upload: its staging is reaped and the answer is 204.
unsafe fn upload_delete(s: &mut State, i: usize) -> bool {
    let slot = s.ex[i].upload_slot as usize;
    reap(s, slot);
    s.ex[i].upload_slot = -1;
    let mut hdr = [0u8; 64];
    let mut h = S3Out::new(&mut hdr);
    h.put(b"x-amz-request-id: ");
    h.put(&s.ex[i].request_id);
    h.put(b"\r\n");
    let hl = h.len;
    stage_head(s, i, 204, b"", &hdr[..hl], b"", true);
    s.ex[i].phase = Phase::Answer;
    true
}

/// Forget upload `slot` and queue its staging for removal.
unsafe fn reap(s: &mut State, slot: usize) {
    let u = s.uploads[slot];
    s.uploads[slot] = UPLOAD_EMPTY;
    if s.reap_len < MAX_UPLOADS {
        let k = s.reap_len;
        s.reap[k] = u.id;
        let bl = u.bucket_len as usize;
        s.reap_bucket[k][..bl].copy_from_slice(&u.name[..bl]);
        s.reap_bucket_len[k] = u.bucket_len;
        s.reap_cred[k] = u.cred;
        s.reap_len += 1;
    }
}

/// Background upkeep: remove queued staging one page at a time, and queue
/// uploads untouched past their lifetime.
unsafe fn sweep(s: &mut State) {
    let now = now_ms(s) / 1000;
    if now >= s.sweep_at {
        s.sweep_at = now + 60;
        for slot in 0..MAX_UPLOADS {
            let u = s.uploads[slot];
            if u.used && !u.busy && now.saturating_sub(u.touched) > UPLOAD_TTL_S {
                reap(s, slot);
            }
        }
    }
    if s.reap_len == 0 {
        return;
    }
    let id = s.reap[0];
    let bl = s.reap_bucket_len[0] as usize;
    let mut bucket = [0u8; S3_BUCKET_MAX];
    bucket[..bl].copy_from_slice(&s.reap_bucket[0][..bl]);
    let grant = s.creds[s.reap_cred[0] as usize].grant;
    let mut marker = [0u8; NAME_MAX];
    let Some(ml) = s3_upload_name(&bucket[..bl], &id, 0, &mut marker) else {
        pop_reap(s);
        return;
    };
    // The parts under `marker/`, then the marker.
    let mut prefix = [0u8; NAME_MAX];
    prefix[..ml].copy_from_slice(&marker[..ml]);
    prefix[ml] = b'/';
    let mut deleted_any = false;
    if let Ok((len, _)) = list_page(s, grant, &prefix[..ml + 1], &[], 64, LIST_PAGE_BUF) {
        let page = core::slice::from_raw_parts(s.page.as_ptr(), len);
        if let Some(p) = obj::list::decode_page(page) {
            for e in p.entries() {
                let mut arg = [0u8; NAME_MAX + 32];
                let mut fence = [0u8; WIRE_MAX_LEN];
                if let Some(n) = delete_arg(&mut arg, e.key, &mut fence) {
                    let _ = obj::write_answer(call(
                        s.syscalls,
                        grant,
                        obj::DELETE,
                        arg.as_mut_ptr(),
                        n,
                    ));
                    deleted_any = true;
                }
            }
        }
    }
    if deleted_any {
        return;
    }
    let mut arg = [0u8; NAME_MAX + 32];
    let mut fence = [0u8; WIRE_MAX_LEN];
    if let Some(n) = delete_arg(&mut arg, &marker[..ml], &mut fence) {
        let _ = obj::write_answer(call(s.syscalls, grant, obj::DELETE, arg.as_mut_ptr(), n));
    }
    pop_reap(s);
}

unsafe fn pop_reap(s: &mut State) {
    let n = s.reap_len;
    for k in 1..n {
        s.reap[k - 1] = s.reap[k];
        s.reap_bucket[k - 1] = s.reap_bucket[k];
        s.reap_bucket_len[k - 1] = s.reap_bucket_len[k];
        s.reap_cred[k - 1] = s.reap_cred[k];
    }
    s.reap_len -= 1;
}
