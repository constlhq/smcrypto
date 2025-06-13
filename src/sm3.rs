//! An implementation of the [SM3] cryptographic hash function defined
#![forbid(unsafe_code)]

pub use digest::Digest;

use crate::sm3::compress::compress;
use core::{fmt, slice::from_ref};
use digest::{
    HashMarker, Output,
    block_buffer::Eager,
    core_api::{
        AlgorithmName, Block, BlockSizeUser, Buffer, BufferKindUser, CoreWrapper, FixedOutputCore,
        OutputSizeUser, Reset, UpdateCore,
    },
    typenum::{U32, U64, Unsigned},
};

/// Core SM3 hasher state.
#[derive(Clone)]
pub struct Sm3Core {
    block_len: u64,
    h: [u32; 8],
}

impl HashMarker for Sm3Core {}

impl BlockSizeUser for Sm3Core {
    type BlockSize = U64;
}

impl BufferKindUser for Sm3Core {
    type BufferKind = Eager;
}

impl OutputSizeUser for Sm3Core {
    type OutputSize = U32;
}

impl UpdateCore for Sm3Core {
    #[inline]
    fn update_blocks(&mut self, blocks: &[Block<Self>]) {
        self.block_len += blocks.len() as u64;
        compress(&mut self.h, blocks);
    }
}

impl FixedOutputCore for Sm3Core {
    #[inline]
    fn finalize_fixed_core(&mut self, buffer: &mut Buffer<Self>, out: &mut Output<Self>) {
        let bs = Self::BlockSize::U64;
        let bit_len = 8 * (buffer.get_pos() as u64 + bs * self.block_len);

        let mut h = self.h;
        buffer.len64_padding_be(bit_len, |b| compress(&mut h, from_ref(b)));
        for (chunk, v) in out.chunks_exact_mut(4).zip(h.iter()) {
            chunk.copy_from_slice(&v.to_be_bytes());
        }
    }
}

impl Default for Sm3Core {
    #[inline]
    fn default() -> Self {
        Self {
            h: consts::H0,
            block_len: 0,
        }
    }
}

impl Reset for Sm3Core {
    #[inline]
    fn reset(&mut self) {
        *self = Default::default();
    }
}

impl AlgorithmName for Sm3Core {
    fn write_alg_name(f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Sm3")
    }
}

impl fmt::Debug for Sm3Core {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Sm3Core { ... }")
    }
}

/// Sm3 hasher state.
pub type Sm3 = CoreWrapper<Sm3Core>;

mod consts {
    #![allow(clippy::unreadable_literal)]

    pub(crate) const T32: [u32; 64] = [
        0x79cc4519, 0xf3988a32, 0xe7311465, 0xce6228cb, 0x9cc45197, 0x3988a32f, 0x7311465e,
        0xe6228cbc, 0xcc451979, 0x988a32f3, 0x311465e7, 0x6228cbce, 0xc451979c, 0x88a32f39,
        0x11465e73, 0x228cbce6, 0x9d8a7a87, 0x3b14f50f, 0x7629ea1e, 0xec53d43c, 0xd8a7a879,
        0xb14f50f3, 0x629ea1e7, 0xc53d43ce, 0x8a7a879d, 0x14f50f3b, 0x29ea1e76, 0x53d43cec,
        0xa7a879d8, 0x4f50f3b1, 0x9ea1e762, 0x3d43cec5, 0x7a879d8a, 0xf50f3b14, 0xea1e7629,
        0xd43cec53, 0xa879d8a7, 0x50f3b14f, 0xa1e7629e, 0x43cec53d, 0x879d8a7a, 0x0f3b14f5,
        0x1e7629ea, 0x3cec53d4, 0x79d8a7a8, 0xf3b14f50, 0xe7629ea1, 0xcec53d43, 0x9d8a7a87,
        0x3b14f50f, 0x7629ea1e, 0xec53d43c, 0xd8a7a879, 0xb14f50f3, 0x629ea1e7, 0xc53d43ce,
        0x8a7a879d, 0x14f50f3b, 0x29ea1e76, 0x53d43cec, 0xa7a879d8, 0x4f50f3b1, 0x9ea1e762,
        0x3d43cec5,
    ];

    pub(crate) static H0: [u32; 8] = [
        0x7380166f, 0x4914b2b9, 0x172442d7, 0xda8a0600, 0xa96f30bc, 0x163138aa, 0xe38dee4d,
        0xb0fb0e4e,
    ];
}

mod compress {
    #![allow(clippy::many_single_char_names, clippy::too_many_arguments)]
    use crate::sm3::Sm3Core;
    use crate::sm3::consts::T32;
    use core::convert::TryInto;
    use digest::core_api::Block;

    #[inline(always)]
    fn ff1(x: u32, y: u32, z: u32) -> u32 {
        x ^ y ^ z
    }

    #[inline(always)]
    fn ff2(x: u32, y: u32, z: u32) -> u32 {
        (x & y) | (x & z) | (y & z)
    }

    #[inline(always)]
    fn gg1(x: u32, y: u32, z: u32) -> u32 {
        x ^ y ^ z
    }

    #[inline(always)]
    fn gg2(x: u32, y: u32, z: u32) -> u32 {
        // This line is equivalent to `(x & y) | (!x & z)`, but executes faster
        (y ^ z) & x ^ z
    }

    #[inline(always)]
    fn p0(x: u32) -> u32 {
        x ^ x.rotate_left(9) ^ x.rotate_left(17)
    }

    #[inline(always)]
    fn p1(x: u32) -> u32 {
        x ^ x.rotate_left(15) ^ x.rotate_left(23)
    }

    #[inline(always)]
    fn w1(x: &[u32; 16], i: usize) -> u32 {
        x[i & 0x0f]
    }

    #[inline(always)]
    fn w2(x: &mut [u32; 16], i: usize) -> u32 {
        let tw = w1(x, i) ^ w1(x, i - 9) ^ w1(x, i - 3).rotate_left(15);
        let tw = p1(tw) ^ w1(x, i - 13).rotate_left(7) ^ w1(x, i - 6);
        x[i & 0x0f] = tw;
        tw
    }

    #[inline(always)]
    fn t(i: usize) -> u32 {
        T32[i]
    }

    fn sm3_round1(
        a: u32,
        b: u32,
        c: u32,
        d: u32,
        e: u32,
        f: u32,
        g: u32,
        h: u32,
        t: u32,
        w1: u32,
        w2: u32,
    ) -> [u32; 8] {
        let ss1 = a
            .rotate_left(12)
            .wrapping_add(e)
            .wrapping_add(t)
            .rotate_left(7);
        let ss2 = ss1 ^ a.rotate_left(12);

        let d = d
            .wrapping_add(ff1(a, b, c))
            .wrapping_add(ss2)
            .wrapping_add(w1 ^ w2);
        let h = h
            .wrapping_add(gg1(e, f, g))
            .wrapping_add(ss1)
            .wrapping_add(w1);
        let b = b.rotate_left(9);
        let f = f.rotate_left(19);
        let h = p0(h);

        [a, b, c, d, e, f, g, h]
    }

    fn sm3_round2(
        a: u32,
        b: u32,
        c: u32,
        d: u32,
        e: u32,
        f: u32,
        g: u32,
        h: u32,
        t: u32,
        w1: u32,
        w2: u32,
    ) -> [u32; 8] {
        let ss1 = (a.rotate_left(12).wrapping_add(e).wrapping_add(t)).rotate_left(7);
        let ss2 = ss1 ^ a.rotate_left(12);

        let d = d
            .wrapping_add(ff2(a, b, c))
            .wrapping_add(ss2)
            .wrapping_add(w1 ^ w2);
        let h = h
            .wrapping_add(gg2(e, f, g))
            .wrapping_add(ss1)
            .wrapping_add(w1);
        let b = b.rotate_left(9);
        let f = f.rotate_left(19);
        let h = p0(h);

        [a, b, c, d, e, f, g, h]
    }

    macro_rules! R1 {
        (
        $a: ident, $b: ident, $c: ident, $d: ident,
        $e: ident, $f: ident, $g: ident, $h: ident,
        $t: expr, $w1: expr, $w2: expr
    ) => {{
            let out = sm3_round1($a, $b, $c, $d, $e, $f, $g, $h, $t, $w1, $w2);
            $a = out[0];
            $b = out[1];
            $c = out[2];
            $d = out[3];
            $e = out[4];
            $f = out[5];
            $g = out[6];
            $h = out[7];
        }};
    }

    macro_rules! R2 {
        (
        $a: ident, $b: ident, $c: ident, $d: ident,
        $e: ident, $f: ident, $g: ident, $h: ident,
        $t: expr, $w1: expr, $w2: expr
    ) => {{
            let out = sm3_round2($a, $b, $c, $d, $e, $f, $g, $h, $t, $w1, $w2);
            $a = out[0];
            $b = out[1];
            $c = out[2];
            $d = out[3];
            $e = out[4];
            $f = out[5];
            $g = out[6];
            $h = out[7];
        }};
    }

    fn compress_u32(state: &mut [u32; 8], block: &[u32; 16]) {
        let mut x: [u32; 16] = *block;

        let mut a = state[0];
        let mut b = state[1];
        let mut c = state[2];
        let mut d = state[3];
        let mut e = state[4];
        let mut f = state[5];
        let mut g = state[6];
        let mut h = state[7];

        R1!(a, b, c, d, e, f, g, h, t(0), w1(&x, 0), w1(&x, 4));
        R1!(d, a, b, c, h, e, f, g, t(1), w1(&x, 1), w1(&x, 5));
        R1!(c, d, a, b, g, h, e, f, t(2), w1(&x, 2), w1(&x, 6));
        R1!(b, c, d, a, f, g, h, e, t(3), w1(&x, 3), w1(&x, 7));
        R1!(a, b, c, d, e, f, g, h, t(4), w1(&x, 4), w1(&x, 8));
        R1!(d, a, b, c, h, e, f, g, t(5), w1(&x, 5), w1(&x, 9));
        R1!(c, d, a, b, g, h, e, f, t(6), w1(&x, 6), w1(&x, 10));
        R1!(b, c, d, a, f, g, h, e, t(7), w1(&x, 7), w1(&x, 11));
        R1!(a, b, c, d, e, f, g, h, t(8), w1(&x, 8), w1(&x, 12));
        R1!(d, a, b, c, h, e, f, g, t(9), w1(&x, 9), w1(&x, 13));
        R1!(c, d, a, b, g, h, e, f, t(10), w1(&x, 10), w1(&x, 14));
        R1!(b, c, d, a, f, g, h, e, t(11), w1(&x, 11), w1(&x, 15));
        R1!(a, b, c, d, e, f, g, h, t(12), w1(&x, 12), w2(&mut x, 16));
        R1!(d, a, b, c, h, e, f, g, t(13), w1(&x, 13), w2(&mut x, 17));
        R1!(c, d, a, b, g, h, e, f, t(14), w1(&x, 14), w2(&mut x, 18));
        R1!(b, c, d, a, f, g, h, e, t(15), w1(&x, 15), w2(&mut x, 19));
        R2!(a, b, c, d, e, f, g, h, t(16), w1(&x, 16), w2(&mut x, 20));
        R2!(d, a, b, c, h, e, f, g, t(17), w1(&x, 17), w2(&mut x, 21));
        R2!(c, d, a, b, g, h, e, f, t(18), w1(&x, 18), w2(&mut x, 22));
        R2!(b, c, d, a, f, g, h, e, t(19), w1(&x, 19), w2(&mut x, 23));
        R2!(a, b, c, d, e, f, g, h, t(20), w1(&x, 20), w2(&mut x, 24));
        R2!(d, a, b, c, h, e, f, g, t(21), w1(&x, 21), w2(&mut x, 25));
        R2!(c, d, a, b, g, h, e, f, t(22), w1(&x, 22), w2(&mut x, 26));
        R2!(b, c, d, a, f, g, h, e, t(23), w1(&x, 23), w2(&mut x, 27));
        R2!(a, b, c, d, e, f, g, h, t(24), w1(&x, 24), w2(&mut x, 28));
        R2!(d, a, b, c, h, e, f, g, t(25), w1(&x, 25), w2(&mut x, 29));
        R2!(c, d, a, b, g, h, e, f, t(26), w1(&x, 26), w2(&mut x, 30));
        R2!(b, c, d, a, f, g, h, e, t(27), w1(&x, 27), w2(&mut x, 31));
        R2!(a, b, c, d, e, f, g, h, t(28), w1(&x, 28), w2(&mut x, 32));
        R2!(d, a, b, c, h, e, f, g, t(29), w1(&x, 29), w2(&mut x, 33));
        R2!(c, d, a, b, g, h, e, f, t(30), w1(&x, 30), w2(&mut x, 34));
        R2!(b, c, d, a, f, g, h, e, t(31), w1(&x, 31), w2(&mut x, 35));
        R2!(a, b, c, d, e, f, g, h, t(32), w1(&x, 32), w2(&mut x, 36));
        R2!(d, a, b, c, h, e, f, g, t(33), w1(&x, 33), w2(&mut x, 37));
        R2!(c, d, a, b, g, h, e, f, t(34), w1(&x, 34), w2(&mut x, 38));
        R2!(b, c, d, a, f, g, h, e, t(35), w1(&x, 35), w2(&mut x, 39));
        R2!(a, b, c, d, e, f, g, h, t(36), w1(&x, 36), w2(&mut x, 40));
        R2!(d, a, b, c, h, e, f, g, t(37), w1(&x, 37), w2(&mut x, 41));
        R2!(c, d, a, b, g, h, e, f, t(38), w1(&x, 38), w2(&mut x, 42));
        R2!(b, c, d, a, f, g, h, e, t(39), w1(&x, 39), w2(&mut x, 43));
        R2!(a, b, c, d, e, f, g, h, t(40), w1(&x, 40), w2(&mut x, 44));
        R2!(d, a, b, c, h, e, f, g, t(41), w1(&x, 41), w2(&mut x, 45));
        R2!(c, d, a, b, g, h, e, f, t(42), w1(&x, 42), w2(&mut x, 46));
        R2!(b, c, d, a, f, g, h, e, t(43), w1(&x, 43), w2(&mut x, 47));
        R2!(a, b, c, d, e, f, g, h, t(44), w1(&x, 44), w2(&mut x, 48));
        R2!(d, a, b, c, h, e, f, g, t(45), w1(&x, 45), w2(&mut x, 49));
        R2!(c, d, a, b, g, h, e, f, t(46), w1(&x, 46), w2(&mut x, 50));
        R2!(b, c, d, a, f, g, h, e, t(47), w1(&x, 47), w2(&mut x, 51));
        R2!(a, b, c, d, e, f, g, h, t(48), w1(&x, 48), w2(&mut x, 52));
        R2!(d, a, b, c, h, e, f, g, t(49), w1(&x, 49), w2(&mut x, 53));
        R2!(c, d, a, b, g, h, e, f, t(50), w1(&x, 50), w2(&mut x, 54));
        R2!(b, c, d, a, f, g, h, e, t(51), w1(&x, 51), w2(&mut x, 55));
        R2!(a, b, c, d, e, f, g, h, t(52), w1(&x, 52), w2(&mut x, 56));
        R2!(d, a, b, c, h, e, f, g, t(53), w1(&x, 53), w2(&mut x, 57));
        R2!(c, d, a, b, g, h, e, f, t(54), w1(&x, 54), w2(&mut x, 58));
        R2!(b, c, d, a, f, g, h, e, t(55), w1(&x, 55), w2(&mut x, 59));
        R2!(a, b, c, d, e, f, g, h, t(56), w1(&x, 56), w2(&mut x, 60));
        R2!(d, a, b, c, h, e, f, g, t(57), w1(&x, 57), w2(&mut x, 61));
        R2!(c, d, a, b, g, h, e, f, t(58), w1(&x, 58), w2(&mut x, 62));
        R2!(b, c, d, a, f, g, h, e, t(59), w1(&x, 59), w2(&mut x, 63));
        R2!(a, b, c, d, e, f, g, h, t(60), w1(&x, 60), w2(&mut x, 64));
        R2!(d, a, b, c, h, e, f, g, t(61), w1(&x, 61), w2(&mut x, 65));
        R2!(c, d, a, b, g, h, e, f, t(62), w1(&x, 62), w2(&mut x, 66));
        R2!(b, c, d, a, f, g, h, e, t(63), w1(&x, 63), w2(&mut x, 67));

        state[0] ^= a;
        state[1] ^= b;
        state[2] ^= c;
        state[3] ^= d;
        state[4] ^= e;
        state[5] ^= f;
        state[6] ^= g;
        state[7] ^= h;
    }

    pub(crate) fn compress(state: &mut [u32; 8], blocks: &[Block<Sm3Core>]) {
        for block in blocks {
            let mut w = [0u32; 16];
            for (o, chunk) in w.iter_mut().zip(block.chunks_exact(4)) {
                *o = u32::from_be_bytes(chunk.try_into().unwrap());
            }
            compress_u32(state, &w);
        }
    }
}

#[cfg(test)]
mod test {
    use crate::sm3::Sm3;
    use digest::Digest;
    use hex_literal::hex;
    #[test]
    fn test() {
        let hasher = Sm3::new();
        let hash = Sm3::digest(b"hello world");
        // let hash = hasher.finalize();

        assert_eq!(
            hash.as_slice(),
            hex!("44f0061e69fa6fdfc290c494654a05dc0c053da7e5c52b84ef93a9d67d3fff88")
        );
    }
}
