//! Constant-time select / equal primitives.
//!
//! All paths are branch-free and LLVM-optimization-resistant.
//! x86_64  → cmov / sete  (via inline asm)
//! aarch64 → csel / cset  (via inline asm)
//! other   → black_box-masked bitwise arithmetic

#![allow(dead_code)]

// ═══════════════════════════════════════════════════════════════════════════
// x86_64
// ═══════════════════════════════════════════════════════════════════════════

/// Returns `a` if `cond != 0`, else `b`.  Uses `cmovnz` — no branch emitted.
#[cfg(target_arch = "x86_64")]
#[must_use]
#[inline]
pub fn select_u8(cond: u8, a: u8, b: u8) -> u8 {
    // x86 has no 8-bit cmov; promote to 32-bit.
    let result: u32;
    unsafe {
        core::arch::asm!(
            "test {c:e}, {c:e}",
            "cmovnz {r:e}, {a:e}",
            c      = in(reg)    cond as u32,
            a      = in(reg)    a    as u32,
            r      = inout(reg) b as u32 => result,
            options(nomem, nostack),
        );
    }
    result as u8
}

/// Returns `a` if `cond != 0`, else `b`.  Uses `cmovnz` — no branch emitted.
#[cfg(target_arch = "x86_64")]
#[must_use]
#[inline]
pub fn select_u32(cond: u8, a: u32, b: u32) -> u32 {
    let result: u32;
    unsafe {
        core::arch::asm!(
            "test {c:e}, {c:e}",
            "cmovnz {r:e}, {a:e}",
            c      = in(reg)    cond as u32,
            a      = in(reg)    a,
            r      = inout(reg) b => result,
            options(nomem, nostack),
        );
    }
    result
}

/// Returns `a` if `cond != 0`, else `b`.  Uses `cmovnz` — no branch emitted.
#[cfg(target_arch = "x86_64")]
#[must_use]
#[inline]
pub fn select_u64(cond: u8, a: u64, b: u64) -> u64 {
    let result: u64;
    unsafe {
        core::arch::asm!(
            "test {c:e}, {c:e}",
            "cmovnz {r}, {a}",
            c      = in(reg)    cond as u32,
            a      = in(reg)    a,
            r      = inout(reg) b => result,
            options(nomem, nostack),
        );
    }
    result
}

/// Returns `1u8` if `a == b`, else `0u8`.  Uses `cmp + sete` — no branch emitted.
#[cfg(target_arch = "x86_64")]
#[must_use]
#[inline]
pub fn equal_u8(a: u8, b: u8) -> u8 {
    let result: u8;
    unsafe {
        core::arch::asm!(
            "cmp {a:e}, {b:e}",
            "sete {r}",
            a = in(reg)      a as u32,
            b = in(reg)      b as u32,
            r = out(reg_byte) result,
            options(nomem, nostack),
        );
    }
    result
}

/// Returns `1u8` if `a == b`, else `0u8`.  Uses `cmp + sete` — no branch emitted.
#[cfg(target_arch = "x86_64")]
#[must_use]
#[inline]
pub fn equal_u32(a: u32, b: u32) -> u8 {
    let result: u8;
    unsafe {
        core::arch::asm!(
            "cmp {a:e}, {b:e}",
            "sete {r}",
            a = in(reg)      a,
            b = in(reg)      b,
            r = out(reg_byte) result,
            options(nomem, nostack),
        );
    }
    result
}

/// Returns `1u8` if `a == b`, else `0u8`.  Uses `cmp + sete` — no branch emitted.
#[cfg(target_arch = "x86_64")]
#[must_use]
#[inline]
pub fn equal_u64(a: u64, b: u64) -> u8 {
    let result: u8;
    unsafe {
        core::arch::asm!(
            "cmp {a}, {b}",
            "sete {r}",
            a = in(reg)      a,
            b = in(reg)      b,
            r = out(reg_byte) result,
            options(nomem, nostack),
        );
    }
    result
}

// ═══════════════════════════════════════════════════════════════════════════
// aarch64
// ═══════════════════════════════════════════════════════════════════════════

/// Returns `a` if `cond != 0`, else `b`.  Uses `csel` — no branch emitted.
#[cfg(target_arch = "aarch64")]
#[must_use]
#[inline]
pub fn select_u8(cond: u8, a: u8, b: u8) -> u8 {
    select_u64(cond, a as u64, b as u64) as u8
}

/// Returns `a` if `cond != 0`, else `b`.  Uses `csel` — no branch emitted.
#[cfg(target_arch = "aarch64")]
#[must_use]
#[inline]
pub fn select_u32(cond: u8, a: u32, b: u32) -> u32 {
    select_u64(cond, a as u64, b as u64) as u32
}

/// Returns `a` if `cond != 0`, else `b`.  Uses `csel` — no branch emitted.
#[cfg(target_arch = "aarch64")]
#[must_use]
#[inline]
pub fn select_u64(cond: u8, a: u64, b: u64) -> u64 {
    let result: u64;
    unsafe {
        core::arch::asm!(
            "cmp {c:w}, #0",
            "csel {r}, {a}, {b}, ne",
            c = in(reg) cond as u64,
            a = in(reg) a,
            b = in(reg) b,
            r = out(reg) result,
            options(nomem, nostack),
        );
    }
    result
}

/// Returns `1u8` if `a == b`, else `0u8`.  Uses `cmp + cset` — no branch emitted.
#[cfg(target_arch = "aarch64")]
#[must_use]
#[inline]
pub fn equal_u8(a: u8, b: u8) -> u8 {
    equal_u64(a as u64, b as u64)
}

/// Returns `1u8` if `a == b`, else `0u8`.  Uses `cmp + cset` — no branch emitted.
#[cfg(target_arch = "aarch64")]
#[must_use]
#[inline]
pub fn equal_u32(a: u32, b: u32) -> u8 {
    equal_u64(a as u64, b as u64)
}

/// Returns `1u8` if `a == b`, else `0u8`.  Uses `cmp + cset` — no branch emitted.
#[cfg(target_arch = "aarch64")]
#[must_use]
#[inline]
pub fn equal_u64(a: u64, b: u64) -> u8 {
    let result: u64;
    unsafe {
        core::arch::asm!(
            "cmp {a}, {b}",
            "cset {r}, eq",
            a = in(reg)  a,
            b = in(reg)  b,
            r = out(reg) result,
            options(nomem, nostack),
        );
    }
    result as u8
}

// ═══════════════════════════════════════════════════════════════════════════
// Generic fallback (any architecture not handled above)
// black_box makes the mask value opaque to LLVM.
// ═══════════════════════════════════════════════════════════════════════════

/// Generates a full-word mask: `0xFF..FF` if `cond != 0`, else `0x00..00`.
///
/// 정규화 원리:
///   `(c | -c) >> 63`  →  c==0 : 0,  c!=0 : 1  (any u8 value)
///   이후 `wrapping_neg(0 or 1)` 으로 완전한 마스크 생성.
///
/// `black_box` prevents LLVM from constant-folding the input.
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
#[inline(never)]  // defeats LTO-assisted inlining + re-optimization
fn ct_mask(cond: u8) -> u64 {
    let c: u64 = core::hint::black_box(cond as u64);
    // (c | -c): c==0 → 0; c!=0 → MSB is always 1 in at least one of c or -c.
    // >> 63: collapses to exactly 0 or 1 — no branch, no data-dependent path.
    let normalized = (c | c.wrapping_neg()) >> 63;
    // 0 → 0x0000_0000_0000_0000
    // 1 → 0xFFFF_FFFF_FFFF_FFFF
    core::hint::black_box(normalized.wrapping_neg())
}

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
#[must_use]
#[inline]
pub fn select_u8(cond: u8, a: u8, b: u8) -> u8 {
    select_u64(cond, a as u64, b as u64) as u8
}

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
#[must_use]
#[inline]
pub fn select_u32(cond: u8, a: u32, b: u32) -> u32 {
    select_u64(cond, a as u64, b as u64) as u32
}

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
#[must_use]
#[inline]
pub fn select_u64(cond: u8, a: u64, b: u64) -> u64 {
    let mask = ct_mask(cond);
    (mask & a) | ((!mask) & b)
}

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
#[must_use]
#[inline]
pub fn equal_u8(a: u8, b: u8) -> u8 {
    equal_u64(a as u64, b as u64)
}

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
#[must_use]
#[inline]
pub fn equal_u32(a: u32, b: u32) -> u8 {
    equal_u64(a as u64, b as u64)
}

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
#[must_use]
#[inline]
pub fn equal_u64(a: u64, b: u64) -> u8 {
    // XOR: 0 iff a == b.
    let diff = a ^ b;
    // 64→32→16→8 bit fold: any set bit in diff propagates into the lowest byte.
    let s = diff | diff.wrapping_shr(32);
    let s = s    | s.wrapping_shr(16);
    let s = s    | s.wrapping_shr(8);
    let byte = core::hint::black_box(s as u8);
    // ct_mask: 0xFF..FF if byte != 0, else 0.
    let nonzero_mask = ct_mask(byte);
    // nonzero_mask == 0xFF..FF when diff != 0  →  equal = 0
    // nonzero_mask == 0x00..00 when diff == 0  →  equal = 1
    (!nonzero_mask & 1) as u8
}

// ═══════════════════════════════════════════════════════════════════════════
// Architecture-independent
// ═══════════════════════════════════════════════════════════════════════════

/// Returns `1u8` if `a` and `b` are byte-for-byte identical, else `0u8`.
///
/// Runs in time proportional to `a.len()` regardless of content.
/// Returns `0` immediately when lengths differ (length is public information).
#[must_use]
#[inline]
pub fn equal_bytes(a: &[u8], b: &[u8]) -> u8 {
    if a.len() != b.len() {
        return 0;
    }
    let mut acc: u8 = 0;
    for i in 0..a.len() {
        // Sequential dependency on acc prevents loop-idiom rewrite.
        acc |= a[i] ^ b[i];
    }
    // equal_u8 uses arch-specific CT comparison; acc == 0 ⟺ all bytes equal.
    equal_u8(acc, 0)
}
