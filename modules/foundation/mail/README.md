# `mail` — RFC 5322 inbound message parser

Turns an inbound message into bounded **format facts** and a streamed body. The
format mechanics live in the host-tested `modules/common/rfc5322.rs`; this
module is the pump around them. What an address means, which conversation a
message belongs to, and whether an attachment is retained are Conclave's; the
format facts are Wave's.

## Why it is a compiled module and not a codec

A message is as large as it happens to be, and it arrives in whatever spans the
ingress produces. The parser therefore holds the header block until it is
complete — the only part it must see whole — parses it once, and forwards
everything after it as it arrives. That is connection-shaped state across many
records, not a stateless transform of one buffer.

## Ports

| Port | Idx | Direction | Content type | Meaning |
| --- | --- | --- | --- | --- |
| `message_in` | 0 | input | `OctetStream` | `MailChunk` spans of an inbound message |
| `facts_out` | 0 | output | `OctetStream` | One `MailFacts` record per message |
| `body_out` | 1 | output | `OctetStream` | `MailBody` or `MailPart` records: the body |

A message begins with a `MAIL_OP_MESSAGE` record carrying a caller-chosen
correlation id, and continues over `MAIL_OP_MORE` records under that id. Every
record this module emits echoes the id.

### What a facts record states

The addresses that parsed (`From`, `Sender`, `Reply-To`, `To`, `Cc`, each
recipient separately), the display name on `From` where there was one, the
subject and date as written, and the `Message-ID`, `In-Reply-To` and
`References` identifiers without their angle brackets and otherwise unaltered.

The identifier fields are reported as evidence, nothing more. Which
conversation a message belongs to is decided above this module, from these
identifiers and the conversation's own bindings: a parser that picked a thread
would be deciding conversation membership from a header the sender chose.

The date is reported verbatim rather than parsed into a timestamp. A date is a
claim by the sender, and turning it into one number hides how much of one.

### What it refuses

A status accompanies every record and says which of these happened:

- the header block does not parse — a bare CR or LF among the fields, a field
  beginning with folding whitespace, a name carrying a forbidden byte, a line
  past the length the standard allows, or no empty line ending the block;
- the header block is larger than the module holds;
- an address field did not parse;
- more facts were found than one record carries.

In each case **no fields are attached at all**. That is deliberate for the
address case in particular: an identity-bearing field repaired into something
plausible is how a message comes to claim a sender it never had, and half a
recipient list names the wrong recipients.

Group address syntax (`friends: a@x, b@y;`) is refused rather than guessed at,
for the same reason.

## Parameters

None. The parser's behaviour is fixed by the format.

## Timing

`timer_class = "agnostic"`. This module reads no clock. It is driven entirely
by the records that arrive and the room downstream has for what it produces, so
a variable cadence changes nothing about what it emits.

## Scope — read this before wiring it

**Structure, not content.** A part's bytes are forwarded as they were sent.
Decoding base64 or quoted-printable is the reader's, using the encoding this
module reports; the mechanics for both live in `modules/common/mime.rs`
alongside the rest of the MIME parsing.

No character-set conversion, and no validation that a part's bytes are the type
it declares.

No transport: something else obtains the message. The first inbound profile
delivers it through an HTTP webhook, which is `http`'s job, not this module's.

No character-set decoding of encoded words (`=?utf-8?B?…?=`) in the subject or
display names. They are reported exactly as the message wrote them.

### Multipart

A message whose `Content-Type` is `multipart/*` with a boundary parameter is
walked: each part gets its own facts record — its index, declared type,
transfer encoding, disposition, filename and `Content-ID` — and its body
arrives as `MailPart` records carrying that index. The preamble before the
first delimiter and the epilogue after the closing one belong to no part and
are discarded.

The part index is in the body record rather than implied by which facts record
came before it. Two ports whose ordering has to be assumed against each other
is a bug waiting for a busy channel.

A filename is reported exactly as the message wrote it: not sanitised, not
resolved, not decoded. A filename repaired into something that looks safe is a
filename the message did not send, and deciding what is safe belongs where the
file is written.

A `multipart/*` type with no usable boundary is walked as a flat body. There is
no structure to follow, and inventing a delimiter would split the body at bytes
the message never marked.

## Status

The module's behavioural contract: a message parses identically however its
bytes are split across records, including a split inside a header value; a
header block is held only until it is complete and never assembled with the
body; the body is forwarded in order and in full; a message with an empty body
still terminates; and every refusal names what was wrong and attaches no guess.

Known gaps, stated rather than implied:

- **`bcm2712` only.** Nothing has needed it from `rp2350`.
- **Nested multipart is not descended.** A part that is itself `multipart/*`
  reaches the caller as that part's raw bytes, with its declared type reported;
  walking it needs a boundary stack this module does not keep yet.
