#!/usr/bin/env bash
# A FLAT MODULE IMAGE CANNOT HOLD A POINTER INTO ITSELF.
#
# A `.fmod` is the linked sections copied out as one flat blob and mapped at
# whatever base the loader picks. No relocations are applied — there is no
# dynamic linker in a module, and the format carries no relocation table — so
# every address baked into the image at link time is wrong at run time by the
# load address. Code is fine: the compiler reaches its own constants with
# PC-relative `adrp`/`add`. DATA is not, and this is the gate for that.
#
# The shape that produces it is ordinary Rust:
#
#     match m {
#         METHOD_GET => b"GET",
#         METHOD_HEAD => b"HEAD",
#         ...
#     }
#
# Eight arms over dense integers, each returning a different `&'static [u8]`,
# and LLVM stops emitting per-arm address arithmetic and builds a lookup table
# of `{pointer, length}` pairs instead. The table lands in `.data.rel.ro` —
# "read-only after relocation", which is the linker saying out loud that it
# needs relocating — and the first read of one of its pointers walks into
# unmapped memory. It is a segfault with no HTTP-level symptom: it lands
# between the connection opening and the first byte going out.
#
# Write the table as offsets into ONE literal instead, as
# `modules/foundation/http/wire/method.rs` does. Integers need no relocation,
# and the single reference to the literal is materialised PC-relative like any
# other constant.
#
# The check reads the PRE-LINK objects, because that is where the relocations
# are still visible as relocations; after linking they are indistinguishable
# from any other eight bytes.
#
# Usage: tools/ci/fmod_pic_relocs.sh [--print]
#   --print   list every absolute relocation found and exit 0
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
MODE="${1:-}"

command -v readelf >/dev/null 2>&1 || {
  echo "SKIP: readelf not available — PIC relocation gate not enforced"; exit 0; }

mapfile -t OBJS < <(find "$ROOT/target/fluxor" -path "*/modules/*.o" -type f 2>/dev/null | sort)
if [ "${#OBJS[@]}" -eq 0 ]; then
  echo "FAIL: no module objects under target/fluxor — run 'fluxor modules build --all' first" >&2
  exit 1
fi

fail=0
found=0

# One pass per object: `readelf -rW` prints a header line naming each
# relocation section, then its entries. Tracking the current section while
# walking the entries is enough, and avoids matching a section name — which
# contains `.`, `[` and a mangled hash — as a regular expression.
scan() {
  readelf -rW "$1" 2>/dev/null | awk '
    /^Relocation section/ {
      sec = $3
      gsub(/\047/, "", sec)
      next
    }
    $3 ~ /^R_/ {
      # Offset Info Type SymValue SymName + Addend
      print sec "\t" $3 "\t" $5
    }
  '
}

for obj in "${OBJS[@]}"; do
  rel="${obj#"$ROOT"/}"
  while IFS=$'\t' read -r sec rtype rsym; do
    [ -n "$rtype" ] || continue

    # Only relocations whose TARGET section is allocatable data. `.rela.text`
    # is not one: a relocation there is resolved into an instruction the
    # compiler chose to make PC-relative.
    case "$sec" in
      .rela.data.rel.ro*|.rela.rodata*|.rela.data*) ;;
      *) continue ;;
    esac
    case "$rtype" in
      R_AARCH64_ABS64|R_AARCH64_ABS32|R_X86_64_64|R_RISCV_64) ;;
      *) continue ;;
    esac

    target="${sec#.rela}"
    found=$((found + 1))

    if [ "$MODE" = "--print" ]; then
      printf '%-46s %-44s %s\n' "$rel" "$target" "$rsym"
      continue
    fi

    # ── The two shapes that are absolute AND never dereferenced ─────────
    #
    # `_KEEP_MEMSET` / `_KEEP_MEMMOVE` are `#[used]` arrays of function
    # pointers in fluxor's SDK (../fluxor/modules/sdk/runtime/intrinsics.rs)
    # that exist only to stop LTO dropping the memory intrinsics. Nothing
    # reads them, so the addresses they hold are never followed.
    case "$target" in
      *_KEEP_MEMSET*|*_KEEP_MEMMOVE*|*_KEEP_MEMCPY*)
        case "$rsym" in
          __aeabi_mem*|memcpy|memset|memmove) continue ;;
        esac
        ;;
    esac
    # A `core::panic::Location` promoted into `.data.rel.ro`: one pointer to
    # the file name a panic would report. Reached only from a panic, and a
    # panicking module is already on its way to abort.
    case "$target" in
      *.Lanon.*)
        [ "$rsym" = ".rodata.str1.1" ] && continue
        ;;
    esac

    echo "FAIL $rel" >&2
    echo "   $target" >&2
    echo "   holds an absolute address of '$rsym', which the flat image cannot relocate." >&2
    fail=1
  done < <(scan "$obj")
done

if [ "$MODE" = "--print" ]; then
  echo
  echo "$found absolute relocation(s) in allocatable data across ${#OBJS[@]} object(s)."
  exit 0
fi

if [ "$fail" -ne 0 ]; then
  echo >&2
  echo "A flat .fmod image is mapped at an arbitrary base with no relocations applied," >&2
  echo "so an address stored in its data is wrong by the load address at every read." >&2
  echo "Store offsets into one literal rather than a table of references — see" >&2
  echo "modules/foundation/http/wire/method.rs." >&2
  exit 1
fi

echo "PASS: no module stores an unrelocatable address in its data (${#OBJS[@]} objects)."
