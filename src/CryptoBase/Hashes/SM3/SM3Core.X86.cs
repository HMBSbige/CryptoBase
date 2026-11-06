namespace CryptoBase.Hashes.SM3;

public partial struct SM3Core
{
	// Hands W[j] and the mixed words W[j] ^ W[j + 4] from the vector code to the rounds; a group of words reuses slots only after their last read.
	[InlineArray(24)]
	private struct X86MessageRing
	{
		private uint _element0;
	}

	[SkipLocalsInit]
	[MethodImpl(MethodImplOptions.NoInlining)]
	private static void ProcessBlocksX86(ref SM3Core hashAlgorithm, ReadOnlySpan<byte> source)
	{
		Debug.Assert(X86Base.X64.IsSupported && Ssse3.IsSupported);
		Debug.Assert(!source.IsEmpty);
		Debug.Assert(source.Length % BlockSizeInBytes is 0);
		Unsafe.SkipInit(out X86MessageRing ring);
		ref uint words = ref ring[0];
		ref byte block0 = ref MemoryMarshal.GetReference(source);
		int remaining = source.Length;
		uint a = hashAlgorithm._v0;
		uint b = hashAlgorithm._v1;
		uint c = hashAlgorithm._v2;
		uint d = hashAlgorithm._v3;
		uint e = hashAlgorithm._v4;
		uint f = hashAlgorithm._v5;
		uint g = hashAlgorithm._v6;
		uint h = hashAlgorithm._v7;
		Vector128<byte> endianMask = Vector128.Create((byte)3, 2, 1, 0, 7, 6, 5, 4, 11, 10, 9, 8, 15, 14, 13, 12);
		// P1(x) = x ^ ROL15(x ^ ROL8(x)), with ROL8 as a byte shuffle.
		Vector128<byte> rol8Mask = Vector128.Create((byte)3, 0, 1, 2, 7, 4, 5, 6, 11, 8, 9, 10, 15, 12, 13, 14);
		// The rounds share these, but each declares its own tt2 and fg: with them shared, the JIT on Linux x64 copies tt2 before rotating it by 17 in P0 rather than rotating it in place, and with a12 or ss1 per round, it spills there.
		uint a12, ss1, a12K;
		Vector128<uint> partial, window13, p1Temp;
		do
		{
			Vector128<uint> q0 = Ssse3.Shuffle(Vector128.LoadUnsafe(ref block0, 0), endianMask).AsUInt32();
			Vector128<uint> q1 = Ssse3.Shuffle(Vector128.LoadUnsafe(ref block0, 16), endianMask).AsUInt32();
			Vector128<uint> q2 = Ssse3.Shuffle(Vector128.LoadUnsafe(ref block0, 32), endianMask).AsUInt32();
			Vector128<uint> q3 = Ssse3.Shuffle(Vector128.LoadUnsafe(ref block0, 48), endianMask).AsUInt32();
			// W[0..15] and the mixed words for j in 0..7.
			q0.StoreUnsafe(ref words, 0);
			q1.StoreUnsafe(ref words, 4);
			q2.StoreUnsafe(ref words, 8);
			q3.StoreUnsafe(ref words, 12);
			(q0 ^ q1).StoreUnsafe(ref words, 16);
			(q1 ^ q2).StoreUnsafe(ref words, 20);
			Vector128<uint> v0 = Sse2.Shuffle(q0, 0x4E);
			Vector128<uint> v1 = Sse2.Shuffle(q0, 0x39);
			Vector128<uint> v2 = q1;
			Vector128<uint> v3 = Ssse3.AlignRight(q2, q1, 12);
			Vector128<uint> v4 = Ssse3.AlignRight(q3, q2, 8);
			Vector128<uint> v5 = Sse2.ShiftRightLogical128BitLane(q3, 4);
			// Round 0; A..D = a,b,c,d, E..H = e,f,g,h.
			a12 = BitOperations.RotateLeft(a, 12);
			uint fgRound0 = f ^ g;
			a12K = a12 + 0x79CC4519U;
			h += Unsafe.Add(ref words, 0);
			d += Unsafe.Add(ref words, 16);
			ss1 = BitOperations.RotateLeft(e + a12K, 7);
			uint tt2Round0 = h + (e ^ fgRound0) + ss1;
			h = tt2Round0 ^ BitOperations.RotateLeft(tt2Round0, 9) ^ BitOperations.RotateLeft(tt2Round0, 17);
			d = d + (a ^ b ^ c) + (ss1 ^ a12);
			b = BitOperations.RotateLeft(b, 9);
			f = BitOperations.RotateLeft(f, 19);
			// Round 1; A..D = d,a,b,c, E..H = h,e,f,g.
			a12 = BitOperations.RotateLeft(d, 12);
			uint fgRound1 = e ^ f;
			a12K = a12 + 0xF3988A32U;
			g += Unsafe.Add(ref words, 1);
			c += Unsafe.Add(ref words, 17);
			ss1 = BitOperations.RotateLeft(h + a12K, 7);
			uint tt2Round1 = g + (h ^ fgRound1) + ss1;
			g = tt2Round1 ^ BitOperations.RotateLeft(tt2Round1, 9) ^ BitOperations.RotateLeft(tt2Round1, 17);
			c = c + (d ^ a ^ b) + (ss1 ^ a12);
			a = BitOperations.RotateLeft(a, 9);
			e = BitOperations.RotateLeft(e, 19);
			// Round 2; A..D = c,d,a,b, E..H = g,h,e,f.
			a12 = BitOperations.RotateLeft(c, 12);
			uint fgRound2 = h ^ e;
			a12K = a12 + 0xE7311465U;
			f += Unsafe.Add(ref words, 2);
			b += Unsafe.Add(ref words, 18);
			ss1 = BitOperations.RotateLeft(g + a12K, 7);
			uint tt2Round2 = f + (g ^ fgRound2) + ss1;
			f = tt2Round2 ^ BitOperations.RotateLeft(tt2Round2, 9) ^ BitOperations.RotateLeft(tt2Round2, 17);
			b = b + (c ^ d ^ a) + (ss1 ^ a12);
			d = BitOperations.RotateLeft(d, 9);
			h = BitOperations.RotateLeft(h, 19);
			// Round 3; A..D = b,c,d,a, E..H = f,g,h,e.
			a12 = BitOperations.RotateLeft(b, 12);
			uint fgRound3 = g ^ h;
			a12K = a12 + 0xCE6228CBU;
			e += Unsafe.Add(ref words, 3);
			a += Unsafe.Add(ref words, 19);
			ss1 = BitOperations.RotateLeft(f + a12K, 7);
			uint tt2Round3 = e + (f ^ fgRound3) + ss1;
			e = tt2Round3 ^ BitOperations.RotateLeft(tt2Round3, 9) ^ BitOperations.RotateLeft(tt2Round3, 17);
			a = a + (b ^ c ^ d) + (ss1 ^ a12);
			c = BitOperations.RotateLeft(c, 9);
			g = BitOperations.RotateLeft(g, 19);
			// Rounds 0..3 have read the mixed words for j in 0..3, so their slots take those for j in 8..11.
			(q2 ^ q3).StoreUnsafe(ref words, 16);
			// Round 4; A..D = a,b,c,d, E..H = e,f,g,h.
			a12 = BitOperations.RotateLeft(a, 12);
			uint fgRound4 = f ^ g;
			a12K = a12 + 0x9CC45197U;
			h += Unsafe.Add(ref words, 4);
			d += Unsafe.Add(ref words, 20);
			ss1 = BitOperations.RotateLeft(e + a12K, 7);
			uint tt2Round4 = h + (e ^ fgRound4) + ss1;
			h = tt2Round4 ^ BitOperations.RotateLeft(tt2Round4, 9) ^ BitOperations.RotateLeft(tt2Round4, 17);
			d = d + (a ^ b ^ c) + (ss1 ^ a12);
			b = BitOperations.RotateLeft(b, 9);
			f = BitOperations.RotateLeft(f, 19);
			// Round 5; A..D = d,a,b,c, E..H = h,e,f,g.
			a12 = BitOperations.RotateLeft(d, 12);
			uint fgRound5 = e ^ f;
			a12K = a12 + 0x3988A32FU;
			g += Unsafe.Add(ref words, 5);
			c += Unsafe.Add(ref words, 21);
			ss1 = BitOperations.RotateLeft(h + a12K, 7);
			uint tt2Round5 = g + (h ^ fgRound5) + ss1;
			g = tt2Round5 ^ BitOperations.RotateLeft(tt2Round5, 9) ^ BitOperations.RotateLeft(tt2Round5, 17);
			c = c + (d ^ a ^ b) + (ss1 ^ a12);
			a = BitOperations.RotateLeft(a, 9);
			e = BitOperations.RotateLeft(e, 19);

			// Rounds 6..8 also compute W[16..18] from v0,v1,v2,v3,v4,v5, the words before them three at a time, oldest first.
			partial = Ssse3.AlignRight(v1, Sse2.Shuffle(v0, 0xBF), 12);
			// Round 6; A..D = c,d,a,b, E..H = g,h,e,f.
			a12 = BitOperations.RotateLeft(c, 12);
			uint fgRound6 = h ^ e;
			a12K = a12 + 0x7311465EU;
			f += Unsafe.Add(ref words, 6);
			b += Unsafe.Add(ref words, 22);
			ss1 = BitOperations.RotateLeft(g + a12K, 7);
			uint tt2Round6 = f + (g ^ fgRound6) + ss1;
			f = tt2Round6 ^ BitOperations.RotateLeft(tt2Round6, 9) ^ BitOperations.RotateLeft(tt2Round6, 17);
			b = b + (c ^ d ^ a) + (ss1 ^ a12);
			d = BitOperations.RotateLeft(d, 9);
			h = BitOperations.RotateLeft(h, 19);
			partial ^= v3 ^ (Avx512F.VL.IsSupported ? Avx512F.VL.RotateLeft(v5, 15) : v5 << 15 | v5 >>> 17);
			window13 = Ssse3.AlignRight(v2, Sse2.Shuffle(v1, 0xBF), 12);
			// Round 7; A..D = b,c,d,a, E..H = f,g,h,e.
			a12 = BitOperations.RotateLeft(b, 12);
			uint fgRound7 = g ^ h;
			a12K = a12 + 0xE6228CBCU;
			e += Unsafe.Add(ref words, 7);
			a += Unsafe.Add(ref words, 23);
			ss1 = BitOperations.RotateLeft(f + a12K, 7);
			uint tt2Round7 = e + (f ^ fgRound7) + ss1;
			e = tt2Round7 ^ BitOperations.RotateLeft(tt2Round7, 9) ^ BitOperations.RotateLeft(tt2Round7, 17);
			a = a + (b ^ c ^ d) + (ss1 ^ a12);
			c = BitOperations.RotateLeft(c, 9);
			g = BitOperations.RotateLeft(g, 19);
			p1Temp = partial ^ Ssse3.Shuffle(partial.AsByte(), rol8Mask).AsUInt32();
			v0 = partial ^ (Avx512F.VL.IsSupported ? Avx512F.VL.RotateLeft(p1Temp, 15) : p1Temp << 15 | p1Temp >>> 17);
			// Round 8; A..D = a,b,c,d, E..H = e,f,g,h.
			a12 = BitOperations.RotateLeft(a, 12);
			uint fgRound8 = f ^ g;
			a12K = a12 + 0xCC451979U;
			h += Unsafe.Add(ref words, 8);
			d += Unsafe.Add(ref words, 16);
			ss1 = BitOperations.RotateLeft(e + a12K, 7);
			uint tt2Round8 = h + (e ^ fgRound8) + ss1;
			h = tt2Round8 ^ BitOperations.RotateLeft(tt2Round8, 9) ^ BitOperations.RotateLeft(tt2Round8, 17);
			d = d + (a ^ b ^ c) + (ss1 ^ a12);
			b = BitOperations.RotateLeft(b, 9);
			f = BitOperations.RotateLeft(f, 19);
			v0 ^= (Avx512F.VL.IsSupported ? Avx512F.VL.RotateLeft(window13, 7) : window13 << 7 | window13 >>> 25) ^ v4;
			// Produced W[16..18]; only still-needed scalar operands are stored.
			v0.StoreUnsafe(ref words, 0);
			(Ssse3.AlignRight(v5, Sse2.Shuffle(v4, 0xBF), 12) ^ v0).StoreUnsafe(ref words, 20);

			// Rounds 9..11 also compute W[19..21] from v1,v2,v3,v4,v5,v0, the words before them three at a time, oldest first.
			partial = Ssse3.AlignRight(v2, Sse2.Shuffle(v1, 0xBF), 12);
			// Round 9; A..D = d,a,b,c, E..H = h,e,f,g.
			a12 = BitOperations.RotateLeft(d, 12);
			uint fgRound9 = e ^ f;
			a12K = a12 + 0x988A32F3U;
			g += Unsafe.Add(ref words, 9);
			c += Unsafe.Add(ref words, 17);
			ss1 = BitOperations.RotateLeft(h + a12K, 7);
			uint tt2Round9 = g + (h ^ fgRound9) + ss1;
			g = tt2Round9 ^ BitOperations.RotateLeft(tt2Round9, 9) ^ BitOperations.RotateLeft(tt2Round9, 17);
			c = c + (d ^ a ^ b) + (ss1 ^ a12);
			a = BitOperations.RotateLeft(a, 9);
			e = BitOperations.RotateLeft(e, 19);
			partial ^= v4 ^ (Avx512F.VL.IsSupported ? Avx512F.VL.RotateLeft(v0, 15) : v0 << 15 | v0 >>> 17);
			window13 = Ssse3.AlignRight(v3, Sse2.Shuffle(v2, 0xBF), 12);
			// Round 10; A..D = c,d,a,b, E..H = g,h,e,f.
			a12 = BitOperations.RotateLeft(c, 12);
			uint fgRound10 = h ^ e;
			a12K = a12 + 0x311465E7U;
			f += Unsafe.Add(ref words, 10);
			b += Unsafe.Add(ref words, 18);
			ss1 = BitOperations.RotateLeft(g + a12K, 7);
			uint tt2Round10 = f + (g ^ fgRound10) + ss1;
			f = tt2Round10 ^ BitOperations.RotateLeft(tt2Round10, 9) ^ BitOperations.RotateLeft(tt2Round10, 17);
			b = b + (c ^ d ^ a) + (ss1 ^ a12);
			d = BitOperations.RotateLeft(d, 9);
			h = BitOperations.RotateLeft(h, 19);
			p1Temp = partial ^ Ssse3.Shuffle(partial.AsByte(), rol8Mask).AsUInt32();
			v1 = partial ^ (Avx512F.VL.IsSupported ? Avx512F.VL.RotateLeft(p1Temp, 15) : p1Temp << 15 | p1Temp >>> 17);
			// Round 11; A..D = b,c,d,a, E..H = f,g,h,e.
			a12 = BitOperations.RotateLeft(b, 12);
			uint fgRound11 = g ^ h;
			a12K = a12 + 0x6228CBCEU;
			e += Unsafe.Add(ref words, 11);
			a += Unsafe.Add(ref words, 19);
			ss1 = BitOperations.RotateLeft(f + a12K, 7);
			uint tt2Round11 = e + (f ^ fgRound11) + ss1;
			e = tt2Round11 ^ BitOperations.RotateLeft(tt2Round11, 9) ^ BitOperations.RotateLeft(tt2Round11, 17);
			a = a + (b ^ c ^ d) + (ss1 ^ a12);
			c = BitOperations.RotateLeft(c, 9);
			g = BitOperations.RotateLeft(g, 19);
			v1 ^= (Avx512F.VL.IsSupported ? Avx512F.VL.RotateLeft(window13, 7) : window13 << 7 | window13 >>> 25) ^ v5;
			// Produced W[19..21]; only still-needed scalar operands are stored.
			v1.StoreUnsafe(ref words, 4);
			(Ssse3.AlignRight(v0, Sse2.Shuffle(v5, 0xBF), 12) ^ v1).StoreUnsafe(ref words, 16);

			// Rounds 12..14 also compute W[22..24] from v2,v3,v4,v5,v0,v1, the words before them three at a time, oldest first.
			partial = Ssse3.AlignRight(v3, Sse2.Shuffle(v2, 0xBF), 12);
			// Round 12; A..D = a,b,c,d, E..H = e,f,g,h.
			a12 = BitOperations.RotateLeft(a, 12);
			uint fgRound12 = f ^ g;
			a12K = a12 + 0xC451979CU;
			h += Unsafe.Add(ref words, 12);
			d += Unsafe.Add(ref words, 20);
			ss1 = BitOperations.RotateLeft(e + a12K, 7);
			uint tt2Round12 = h + (e ^ fgRound12) + ss1;
			h = tt2Round12 ^ BitOperations.RotateLeft(tt2Round12, 9) ^ BitOperations.RotateLeft(tt2Round12, 17);
			d = d + (a ^ b ^ c) + (ss1 ^ a12);
			b = BitOperations.RotateLeft(b, 9);
			f = BitOperations.RotateLeft(f, 19);
			partial ^= v5 ^ (Avx512F.VL.IsSupported ? Avx512F.VL.RotateLeft(v1, 15) : v1 << 15 | v1 >>> 17);
			window13 = Ssse3.AlignRight(v4, Sse2.Shuffle(v3, 0xBF), 12);
			// Round 13; A..D = d,a,b,c, E..H = h,e,f,g.
			a12 = BitOperations.RotateLeft(d, 12);
			uint fgRound13 = e ^ f;
			a12K = a12 + 0x88A32F39U;
			g += Unsafe.Add(ref words, 13);
			c += Unsafe.Add(ref words, 21);
			ss1 = BitOperations.RotateLeft(h + a12K, 7);
			uint tt2Round13 = g + (h ^ fgRound13) + ss1;
			g = tt2Round13 ^ BitOperations.RotateLeft(tt2Round13, 9) ^ BitOperations.RotateLeft(tt2Round13, 17);
			c = c + (d ^ a ^ b) + (ss1 ^ a12);
			a = BitOperations.RotateLeft(a, 9);
			e = BitOperations.RotateLeft(e, 19);
			p1Temp = partial ^ Ssse3.Shuffle(partial.AsByte(), rol8Mask).AsUInt32();
			v2 = partial ^ (Avx512F.VL.IsSupported ? Avx512F.VL.RotateLeft(p1Temp, 15) : p1Temp << 15 | p1Temp >>> 17);
			// Round 14; A..D = c,d,a,b, E..H = g,h,e,f.
			a12 = BitOperations.RotateLeft(c, 12);
			uint fgRound14 = h ^ e;
			a12K = a12 + 0x11465E73U;
			f += Unsafe.Add(ref words, 14);
			b += Unsafe.Add(ref words, 22);
			ss1 = BitOperations.RotateLeft(g + a12K, 7);
			uint tt2Round14 = f + (g ^ fgRound14) + ss1;
			f = tt2Round14 ^ BitOperations.RotateLeft(tt2Round14, 9) ^ BitOperations.RotateLeft(tt2Round14, 17);
			b = b + (c ^ d ^ a) + (ss1 ^ a12);
			d = BitOperations.RotateLeft(d, 9);
			h = BitOperations.RotateLeft(h, 19);
			v2 ^= (Avx512F.VL.IsSupported ? Avx512F.VL.RotateLeft(window13, 7) : window13 << 7 | window13 >>> 25) ^ v0;
			// Produced W[22..24]; only still-needed scalar operands are stored.
			v2.StoreUnsafe(ref words, 8);
			(Ssse3.AlignRight(v1, Sse2.Shuffle(v0, 0xBF), 12) ^ v2).StoreUnsafe(ref words, 20);

			// Rounds 15..17 also compute W[25..27] from v3,v4,v5,v0,v1,v2, the words before them three at a time, oldest first.
			partial = Ssse3.AlignRight(v4, Sse2.Shuffle(v3, 0xBF), 12);
			// Round 15; A..D = b,c,d,a, E..H = f,g,h,e.
			a12 = BitOperations.RotateLeft(b, 12);
			uint fgRound15 = g ^ h;
			a12K = a12 + 0x228CBCE6U;
			e += Unsafe.Add(ref words, 15);
			a += Unsafe.Add(ref words, 16);
			ss1 = BitOperations.RotateLeft(f + a12K, 7);
			uint tt2Round15 = e + (f ^ fgRound15) + ss1;
			e = tt2Round15 ^ BitOperations.RotateLeft(tt2Round15, 9) ^ BitOperations.RotateLeft(tt2Round15, 17);
			a = a + (b ^ c ^ d) + (ss1 ^ a12);
			c = BitOperations.RotateLeft(c, 9);
			g = BitOperations.RotateLeft(g, 19);
			partial ^= v0 ^ (Avx512F.VL.IsSupported ? Avx512F.VL.RotateLeft(v2, 15) : v2 << 15 | v2 >>> 17);
			window13 = Ssse3.AlignRight(v5, Sse2.Shuffle(v4, 0xBF), 12);
			// Round 16; A..D = a,b,c,d, E..H = e,f,g,h.
			a12 = BitOperations.RotateLeft(a, 12);
			uint fgRound16 = f ^ g;
			a12K = a12 + 0x9D8A7A87U;
			h += Unsafe.Add(ref words, 0);
			d += Unsafe.Add(ref words, 17);
			ss1 = BitOperations.RotateLeft(e + a12K, 7);
			uint tt2Round16 = h + (fgRound16 & e ^ g) + ss1;
			h = tt2Round16 ^ BitOperations.RotateLeft(tt2Round16, 9) ^ BitOperations.RotateLeft(tt2Round16, 17);
			d = d + (a & (b | c) | b & c) + (ss1 ^ a12);
			b = BitOperations.RotateLeft(b, 9);
			f = BitOperations.RotateLeft(f, 19);
			p1Temp = partial ^ Ssse3.Shuffle(partial.AsByte(), rol8Mask).AsUInt32();
			v3 = partial ^ (Avx512F.VL.IsSupported ? Avx512F.VL.RotateLeft(p1Temp, 15) : p1Temp << 15 | p1Temp >>> 17);
			// Round 17; A..D = d,a,b,c, E..H = h,e,f,g.
			a12 = BitOperations.RotateLeft(d, 12);
			uint fgRound17 = e ^ f;
			a12K = a12 + 0x3B14F50FU;
			g += Unsafe.Add(ref words, 1);
			c += Unsafe.Add(ref words, 18);
			ss1 = BitOperations.RotateLeft(h + a12K, 7);
			uint tt2Round17 = g + (fgRound17 & h ^ f) + ss1;
			g = tt2Round17 ^ BitOperations.RotateLeft(tt2Round17, 9) ^ BitOperations.RotateLeft(tt2Round17, 17);
			c = c + (d & (a | b) | a & b) + (ss1 ^ a12);
			a = BitOperations.RotateLeft(a, 9);
			e = BitOperations.RotateLeft(e, 19);
			v3 ^= (Avx512F.VL.IsSupported ? Avx512F.VL.RotateLeft(window13, 7) : window13 << 7 | window13 >>> 25) ^ v1;
			// Produced W[25..27]; only still-needed scalar operands are stored.
			v3.StoreUnsafe(ref words, 12);
			(Ssse3.AlignRight(v2, Sse2.Shuffle(v1, 0xBF), 12) ^ v3).StoreUnsafe(ref words, 16);

			// Rounds 18..20 also compute W[28..30] from v4,v5,v0,v1,v2,v3, the words before them three at a time, oldest first.
			partial = Ssse3.AlignRight(v5, Sse2.Shuffle(v4, 0xBF), 12);
			// Round 18; A..D = c,d,a,b, E..H = g,h,e,f.
			a12 = BitOperations.RotateLeft(c, 12);
			uint fgRound18 = h ^ e;
			a12K = a12 + 0x7629EA1EU;
			f += Unsafe.Add(ref words, 2);
			b += Unsafe.Add(ref words, 20);
			ss1 = BitOperations.RotateLeft(g + a12K, 7);
			uint tt2Round18 = f + (fgRound18 & g ^ e) + ss1;
			f = tt2Round18 ^ BitOperations.RotateLeft(tt2Round18, 9) ^ BitOperations.RotateLeft(tt2Round18, 17);
			b = b + (c & (d | a) | d & a) + (ss1 ^ a12);
			d = BitOperations.RotateLeft(d, 9);
			h = BitOperations.RotateLeft(h, 19);
			partial ^= v1 ^ (Avx512F.VL.IsSupported ? Avx512F.VL.RotateLeft(v3, 15) : v3 << 15 | v3 >>> 17);
			window13 = Ssse3.AlignRight(v0, Sse2.Shuffle(v5, 0xBF), 12);
			// Round 19; A..D = b,c,d,a, E..H = f,g,h,e.
			a12 = BitOperations.RotateLeft(b, 12);
			uint fgRound19 = g ^ h;
			a12K = a12 + 0xEC53D43CU;
			e += Unsafe.Add(ref words, 4);
			a += Unsafe.Add(ref words, 21);
			ss1 = BitOperations.RotateLeft(f + a12K, 7);
			uint tt2Round19 = e + (fgRound19 & f ^ h) + ss1;
			e = tt2Round19 ^ BitOperations.RotateLeft(tt2Round19, 9) ^ BitOperations.RotateLeft(tt2Round19, 17);
			a = a + (b & (c | d) | c & d) + (ss1 ^ a12);
			c = BitOperations.RotateLeft(c, 9);
			g = BitOperations.RotateLeft(g, 19);
			p1Temp = partial ^ Ssse3.Shuffle(partial.AsByte(), rol8Mask).AsUInt32();
			v4 = partial ^ (Avx512F.VL.IsSupported ? Avx512F.VL.RotateLeft(p1Temp, 15) : p1Temp << 15 | p1Temp >>> 17);
			// Round 20; A..D = a,b,c,d, E..H = e,f,g,h.
			a12 = BitOperations.RotateLeft(a, 12);
			uint fgRound20 = f ^ g;
			a12K = a12 + 0xD8A7A879U;
			h += Unsafe.Add(ref words, 5);
			d += Unsafe.Add(ref words, 22);
			ss1 = BitOperations.RotateLeft(e + a12K, 7);
			uint tt2Round20 = h + (fgRound20 & e ^ g) + ss1;
			h = tt2Round20 ^ BitOperations.RotateLeft(tt2Round20, 9) ^ BitOperations.RotateLeft(tt2Round20, 17);
			d = d + (a & (b | c) | b & c) + (ss1 ^ a12);
			b = BitOperations.RotateLeft(b, 9);
			f = BitOperations.RotateLeft(f, 19);
			v4 ^= (Avx512F.VL.IsSupported ? Avx512F.VL.RotateLeft(window13, 7) : window13 << 7 | window13 >>> 25) ^ v2;
			// Produced W[28..30]; only still-needed scalar operands are stored.
			v4.StoreUnsafe(ref words, 0);
			(Ssse3.AlignRight(v3, Sse2.Shuffle(v2, 0xBF), 12) ^ v4).StoreUnsafe(ref words, 20);

			// Rounds 21..23 also compute W[31..33] from v5,v0,v1,v2,v3,v4, the words before them three at a time, oldest first.
			partial = Ssse3.AlignRight(v0, Sse2.Shuffle(v5, 0xBF), 12);
			// Round 21; A..D = d,a,b,c, E..H = h,e,f,g.
			a12 = BitOperations.RotateLeft(d, 12);
			uint fgRound21 = e ^ f;
			a12K = a12 + 0xB14F50F3U;
			g += Unsafe.Add(ref words, 6);
			c += Unsafe.Add(ref words, 16);
			ss1 = BitOperations.RotateLeft(h + a12K, 7);
			uint tt2Round21 = g + (fgRound21 & h ^ f) + ss1;
			g = tt2Round21 ^ BitOperations.RotateLeft(tt2Round21, 9) ^ BitOperations.RotateLeft(tt2Round21, 17);
			c = c + (d & (a | b) | a & b) + (ss1 ^ a12);
			a = BitOperations.RotateLeft(a, 9);
			e = BitOperations.RotateLeft(e, 19);
			partial ^= v2 ^ (Avx512F.VL.IsSupported ? Avx512F.VL.RotateLeft(v4, 15) : v4 << 15 | v4 >>> 17);
			window13 = Ssse3.AlignRight(v1, Sse2.Shuffle(v0, 0xBF), 12);
			// Round 22; A..D = c,d,a,b, E..H = g,h,e,f.
			a12 = BitOperations.RotateLeft(c, 12);
			uint fgRound22 = h ^ e;
			a12K = a12 + 0x629EA1E7U;
			f += Unsafe.Add(ref words, 8);
			b += Unsafe.Add(ref words, 17);
			ss1 = BitOperations.RotateLeft(g + a12K, 7);
			uint tt2Round22 = f + (fgRound22 & g ^ e) + ss1;
			f = tt2Round22 ^ BitOperations.RotateLeft(tt2Round22, 9) ^ BitOperations.RotateLeft(tt2Round22, 17);
			b = b + (c & (d | a) | d & a) + (ss1 ^ a12);
			d = BitOperations.RotateLeft(d, 9);
			h = BitOperations.RotateLeft(h, 19);
			p1Temp = partial ^ Ssse3.Shuffle(partial.AsByte(), rol8Mask).AsUInt32();
			v5 = partial ^ (Avx512F.VL.IsSupported ? Avx512F.VL.RotateLeft(p1Temp, 15) : p1Temp << 15 | p1Temp >>> 17);
			// Round 23; A..D = b,c,d,a, E..H = f,g,h,e.
			a12 = BitOperations.RotateLeft(b, 12);
			uint fgRound23 = g ^ h;
			a12K = a12 + 0xC53D43CEU;
			e += Unsafe.Add(ref words, 9);
			a += Unsafe.Add(ref words, 18);
			ss1 = BitOperations.RotateLeft(f + a12K, 7);
			uint tt2Round23 = e + (fgRound23 & f ^ h) + ss1;
			e = tt2Round23 ^ BitOperations.RotateLeft(tt2Round23, 9) ^ BitOperations.RotateLeft(tt2Round23, 17);
			a = a + (b & (c | d) | c & d) + (ss1 ^ a12);
			c = BitOperations.RotateLeft(c, 9);
			g = BitOperations.RotateLeft(g, 19);
			v5 ^= (Avx512F.VL.IsSupported ? Avx512F.VL.RotateLeft(window13, 7) : window13 << 7 | window13 >>> 25) ^ v3;
			// Produced W[31..33]; only still-needed scalar operands are stored.
			v5.StoreUnsafe(ref words, 4);
			(Ssse3.AlignRight(v4, Sse2.Shuffle(v3, 0xBF), 12) ^ v5).StoreUnsafe(ref words, 16);

			// Rounds 24..26 also compute W[34..36] from v0,v1,v2,v3,v4,v5, the words before them three at a time, oldest first.
			partial = Ssse3.AlignRight(v1, Sse2.Shuffle(v0, 0xBF), 12);
			// Round 24; A..D = a,b,c,d, E..H = e,f,g,h.
			a12 = BitOperations.RotateLeft(a, 12);
			uint fgRound24 = f ^ g;
			a12K = a12 + 0x8A7A879DU;
			h += Unsafe.Add(ref words, 10);
			d += Unsafe.Add(ref words, 20);
			ss1 = BitOperations.RotateLeft(e + a12K, 7);
			uint tt2Round24 = h + (fgRound24 & e ^ g) + ss1;
			h = tt2Round24 ^ BitOperations.RotateLeft(tt2Round24, 9) ^ BitOperations.RotateLeft(tt2Round24, 17);
			d = d + (a & (b | c) | b & c) + (ss1 ^ a12);
			b = BitOperations.RotateLeft(b, 9);
			f = BitOperations.RotateLeft(f, 19);
			partial ^= v3 ^ (Avx512F.VL.IsSupported ? Avx512F.VL.RotateLeft(v5, 15) : v5 << 15 | v5 >>> 17);
			window13 = Ssse3.AlignRight(v2, Sse2.Shuffle(v1, 0xBF), 12);
			// Round 25; A..D = d,a,b,c, E..H = h,e,f,g.
			a12 = BitOperations.RotateLeft(d, 12);
			uint fgRound25 = e ^ f;
			a12K = a12 + 0x14F50F3BU;
			g += Unsafe.Add(ref words, 12);
			c += Unsafe.Add(ref words, 21);
			ss1 = BitOperations.RotateLeft(h + a12K, 7);
			uint tt2Round25 = g + (fgRound25 & h ^ f) + ss1;
			g = tt2Round25 ^ BitOperations.RotateLeft(tt2Round25, 9) ^ BitOperations.RotateLeft(tt2Round25, 17);
			c = c + (d & (a | b) | a & b) + (ss1 ^ a12);
			a = BitOperations.RotateLeft(a, 9);
			e = BitOperations.RotateLeft(e, 19);
			p1Temp = partial ^ Ssse3.Shuffle(partial.AsByte(), rol8Mask).AsUInt32();
			v0 = partial ^ (Avx512F.VL.IsSupported ? Avx512F.VL.RotateLeft(p1Temp, 15) : p1Temp << 15 | p1Temp >>> 17);
			// Round 26; A..D = c,d,a,b, E..H = g,h,e,f.
			a12 = BitOperations.RotateLeft(c, 12);
			uint fgRound26 = h ^ e;
			a12K = a12 + 0x29EA1E76U;
			f += Unsafe.Add(ref words, 13);
			b += Unsafe.Add(ref words, 22);
			ss1 = BitOperations.RotateLeft(g + a12K, 7);
			uint tt2Round26 = f + (fgRound26 & g ^ e) + ss1;
			f = tt2Round26 ^ BitOperations.RotateLeft(tt2Round26, 9) ^ BitOperations.RotateLeft(tt2Round26, 17);
			b = b + (c & (d | a) | d & a) + (ss1 ^ a12);
			d = BitOperations.RotateLeft(d, 9);
			h = BitOperations.RotateLeft(h, 19);
			v0 ^= (Avx512F.VL.IsSupported ? Avx512F.VL.RotateLeft(window13, 7) : window13 << 7 | window13 >>> 25) ^ v4;
			// Produced W[34..36]; only still-needed scalar operands are stored.
			v0.StoreUnsafe(ref words, 8);
			(Ssse3.AlignRight(v5, Sse2.Shuffle(v4, 0xBF), 12) ^ v0).StoreUnsafe(ref words, 20);

			// Rounds 27..29 also compute W[37..39] from v1,v2,v3,v4,v5,v0, the words before them three at a time, oldest first.
			partial = Ssse3.AlignRight(v2, Sse2.Shuffle(v1, 0xBF), 12);
			// Round 27; A..D = b,c,d,a, E..H = f,g,h,e.
			a12 = BitOperations.RotateLeft(b, 12);
			uint fgRound27 = g ^ h;
			a12K = a12 + 0x53D43CECU;
			e += Unsafe.Add(ref words, 14);
			a += Unsafe.Add(ref words, 16);
			ss1 = BitOperations.RotateLeft(f + a12K, 7);
			uint tt2Round27 = e + (fgRound27 & f ^ h) + ss1;
			e = tt2Round27 ^ BitOperations.RotateLeft(tt2Round27, 9) ^ BitOperations.RotateLeft(tt2Round27, 17);
			a = a + (b & (c | d) | c & d) + (ss1 ^ a12);
			c = BitOperations.RotateLeft(c, 9);
			g = BitOperations.RotateLeft(g, 19);
			partial ^= v4 ^ (Avx512F.VL.IsSupported ? Avx512F.VL.RotateLeft(v0, 15) : v0 << 15 | v0 >>> 17);
			window13 = Ssse3.AlignRight(v3, Sse2.Shuffle(v2, 0xBF), 12);
			// Round 28; A..D = a,b,c,d, E..H = e,f,g,h.
			a12 = BitOperations.RotateLeft(a, 12);
			uint fgRound28 = f ^ g;
			a12K = a12 + 0xA7A879D8U;
			h += Unsafe.Add(ref words, 0);
			d += Unsafe.Add(ref words, 17);
			ss1 = BitOperations.RotateLeft(e + a12K, 7);
			uint tt2Round28 = h + (fgRound28 & e ^ g) + ss1;
			h = tt2Round28 ^ BitOperations.RotateLeft(tt2Round28, 9) ^ BitOperations.RotateLeft(tt2Round28, 17);
			d = d + (a & (b | c) | b & c) + (ss1 ^ a12);
			b = BitOperations.RotateLeft(b, 9);
			f = BitOperations.RotateLeft(f, 19);
			p1Temp = partial ^ Ssse3.Shuffle(partial.AsByte(), rol8Mask).AsUInt32();
			v1 = partial ^ (Avx512F.VL.IsSupported ? Avx512F.VL.RotateLeft(p1Temp, 15) : p1Temp << 15 | p1Temp >>> 17);
			// Round 29; A..D = d,a,b,c, E..H = h,e,f,g.
			a12 = BitOperations.RotateLeft(d, 12);
			uint fgRound29 = e ^ f;
			a12K = a12 + 0x4F50F3B1U;
			g += Unsafe.Add(ref words, 1);
			c += Unsafe.Add(ref words, 18);
			ss1 = BitOperations.RotateLeft(h + a12K, 7);
			uint tt2Round29 = g + (fgRound29 & h ^ f) + ss1;
			g = tt2Round29 ^ BitOperations.RotateLeft(tt2Round29, 9) ^ BitOperations.RotateLeft(tt2Round29, 17);
			c = c + (d & (a | b) | a & b) + (ss1 ^ a12);
			a = BitOperations.RotateLeft(a, 9);
			e = BitOperations.RotateLeft(e, 19);
			v1 ^= (Avx512F.VL.IsSupported ? Avx512F.VL.RotateLeft(window13, 7) : window13 << 7 | window13 >>> 25) ^ v5;
			// Produced W[37..39]; only still-needed scalar operands are stored.
			v1.StoreUnsafe(ref words, 12);
			(Ssse3.AlignRight(v0, Sse2.Shuffle(v5, 0xBF), 12) ^ v1).StoreUnsafe(ref words, 16);

			// Rounds 30..32 also compute W[40..42] from v2,v3,v4,v5,v0,v1, the words before them three at a time, oldest first.
			partial = Ssse3.AlignRight(v3, Sse2.Shuffle(v2, 0xBF), 12);
			// Round 30; A..D = c,d,a,b, E..H = g,h,e,f.
			a12 = BitOperations.RotateLeft(c, 12);
			uint fgRound30 = h ^ e;
			a12K = a12 + 0x9EA1E762U;
			f += Unsafe.Add(ref words, 2);
			b += Unsafe.Add(ref words, 20);
			ss1 = BitOperations.RotateLeft(g + a12K, 7);
			uint tt2Round30 = f + (fgRound30 & g ^ e) + ss1;
			f = tt2Round30 ^ BitOperations.RotateLeft(tt2Round30, 9) ^ BitOperations.RotateLeft(tt2Round30, 17);
			b = b + (c & (d | a) | d & a) + (ss1 ^ a12);
			d = BitOperations.RotateLeft(d, 9);
			h = BitOperations.RotateLeft(h, 19);
			partial ^= v5 ^ (Avx512F.VL.IsSupported ? Avx512F.VL.RotateLeft(v1, 15) : v1 << 15 | v1 >>> 17);
			window13 = Ssse3.AlignRight(v4, Sse2.Shuffle(v3, 0xBF), 12);
			// Round 31; A..D = b,c,d,a, E..H = f,g,h,e.
			a12 = BitOperations.RotateLeft(b, 12);
			uint fgRound31 = g ^ h;
			a12K = a12 + 0x3D43CEC5U;
			e += Unsafe.Add(ref words, 4);
			a += Unsafe.Add(ref words, 21);
			ss1 = BitOperations.RotateLeft(f + a12K, 7);
			uint tt2Round31 = e + (fgRound31 & f ^ h) + ss1;
			e = tt2Round31 ^ BitOperations.RotateLeft(tt2Round31, 9) ^ BitOperations.RotateLeft(tt2Round31, 17);
			a = a + (b & (c | d) | c & d) + (ss1 ^ a12);
			c = BitOperations.RotateLeft(c, 9);
			g = BitOperations.RotateLeft(g, 19);
			p1Temp = partial ^ Ssse3.Shuffle(partial.AsByte(), rol8Mask).AsUInt32();
			v2 = partial ^ (Avx512F.VL.IsSupported ? Avx512F.VL.RotateLeft(p1Temp, 15) : p1Temp << 15 | p1Temp >>> 17);
			// Round 32; A..D = a,b,c,d, E..H = e,f,g,h.
			a12 = BitOperations.RotateLeft(a, 12);
			uint fgRound32 = f ^ g;
			a12K = a12 + 0x7A879D8AU;
			h += Unsafe.Add(ref words, 5);
			d += Unsafe.Add(ref words, 22);
			ss1 = BitOperations.RotateLeft(e + a12K, 7);
			uint tt2Round32 = h + (fgRound32 & e ^ g) + ss1;
			h = tt2Round32 ^ BitOperations.RotateLeft(tt2Round32, 9) ^ BitOperations.RotateLeft(tt2Round32, 17);
			d = d + (a & (b | c) | b & c) + (ss1 ^ a12);
			b = BitOperations.RotateLeft(b, 9);
			f = BitOperations.RotateLeft(f, 19);
			v2 ^= (Avx512F.VL.IsSupported ? Avx512F.VL.RotateLeft(window13, 7) : window13 << 7 | window13 >>> 25) ^ v0;
			// Produced W[40..42]; only still-needed scalar operands are stored.
			v2.StoreUnsafe(ref words, 0);
			(Ssse3.AlignRight(v1, Sse2.Shuffle(v0, 0xBF), 12) ^ v2).StoreUnsafe(ref words, 20);

			// Rounds 33..35 also compute W[43..45] from v3,v4,v5,v0,v1,v2, the words before them three at a time, oldest first.
			partial = Ssse3.AlignRight(v4, Sse2.Shuffle(v3, 0xBF), 12);
			// Round 33; A..D = d,a,b,c, E..H = h,e,f,g.
			a12 = BitOperations.RotateLeft(d, 12);
			uint fgRound33 = e ^ f;
			a12K = a12 + 0xF50F3B14U;
			g += Unsafe.Add(ref words, 6);
			c += Unsafe.Add(ref words, 16);
			ss1 = BitOperations.RotateLeft(h + a12K, 7);
			uint tt2Round33 = g + (fgRound33 & h ^ f) + ss1;
			g = tt2Round33 ^ BitOperations.RotateLeft(tt2Round33, 9) ^ BitOperations.RotateLeft(tt2Round33, 17);
			c = c + (d & (a | b) | a & b) + (ss1 ^ a12);
			a = BitOperations.RotateLeft(a, 9);
			e = BitOperations.RotateLeft(e, 19);
			partial ^= v0 ^ (Avx512F.VL.IsSupported ? Avx512F.VL.RotateLeft(v2, 15) : v2 << 15 | v2 >>> 17);
			window13 = Ssse3.AlignRight(v5, Sse2.Shuffle(v4, 0xBF), 12);
			// Round 34; A..D = c,d,a,b, E..H = g,h,e,f.
			a12 = BitOperations.RotateLeft(c, 12);
			uint fgRound34 = h ^ e;
			a12K = a12 + 0xEA1E7629U;
			f += Unsafe.Add(ref words, 8);
			b += Unsafe.Add(ref words, 17);
			ss1 = BitOperations.RotateLeft(g + a12K, 7);
			uint tt2Round34 = f + (fgRound34 & g ^ e) + ss1;
			f = tt2Round34 ^ BitOperations.RotateLeft(tt2Round34, 9) ^ BitOperations.RotateLeft(tt2Round34, 17);
			b = b + (c & (d | a) | d & a) + (ss1 ^ a12);
			d = BitOperations.RotateLeft(d, 9);
			h = BitOperations.RotateLeft(h, 19);
			p1Temp = partial ^ Ssse3.Shuffle(partial.AsByte(), rol8Mask).AsUInt32();
			v3 = partial ^ (Avx512F.VL.IsSupported ? Avx512F.VL.RotateLeft(p1Temp, 15) : p1Temp << 15 | p1Temp >>> 17);
			// Round 35; A..D = b,c,d,a, E..H = f,g,h,e.
			a12 = BitOperations.RotateLeft(b, 12);
			uint fgRound35 = g ^ h;
			a12K = a12 + 0xD43CEC53U;
			e += Unsafe.Add(ref words, 9);
			a += Unsafe.Add(ref words, 18);
			ss1 = BitOperations.RotateLeft(f + a12K, 7);
			uint tt2Round35 = e + (fgRound35 & f ^ h) + ss1;
			e = tt2Round35 ^ BitOperations.RotateLeft(tt2Round35, 9) ^ BitOperations.RotateLeft(tt2Round35, 17);
			a = a + (b & (c | d) | c & d) + (ss1 ^ a12);
			c = BitOperations.RotateLeft(c, 9);
			g = BitOperations.RotateLeft(g, 19);
			v3 ^= (Avx512F.VL.IsSupported ? Avx512F.VL.RotateLeft(window13, 7) : window13 << 7 | window13 >>> 25) ^ v1;
			// Produced W[43..45]; only still-needed scalar operands are stored.
			v3.StoreUnsafe(ref words, 4);
			(Ssse3.AlignRight(v2, Sse2.Shuffle(v1, 0xBF), 12) ^ v3).StoreUnsafe(ref words, 16);

			// Rounds 36..38 also compute W[46..48] from v4,v5,v0,v1,v2,v3, the words before them three at a time, oldest first.
			partial = Ssse3.AlignRight(v5, Sse2.Shuffle(v4, 0xBF), 12);
			// Round 36; A..D = a,b,c,d, E..H = e,f,g,h.
			a12 = BitOperations.RotateLeft(a, 12);
			uint fgRound36 = f ^ g;
			a12K = a12 + 0xA879D8A7U;
			h += Unsafe.Add(ref words, 10);
			d += Unsafe.Add(ref words, 20);
			ss1 = BitOperations.RotateLeft(e + a12K, 7);
			uint tt2Round36 = h + (fgRound36 & e ^ g) + ss1;
			h = tt2Round36 ^ BitOperations.RotateLeft(tt2Round36, 9) ^ BitOperations.RotateLeft(tt2Round36, 17);
			d = d + (a & (b | c) | b & c) + (ss1 ^ a12);
			b = BitOperations.RotateLeft(b, 9);
			f = BitOperations.RotateLeft(f, 19);
			partial ^= v1 ^ (Avx512F.VL.IsSupported ? Avx512F.VL.RotateLeft(v3, 15) : v3 << 15 | v3 >>> 17);
			window13 = Ssse3.AlignRight(v0, Sse2.Shuffle(v5, 0xBF), 12);
			// Round 37; A..D = d,a,b,c, E..H = h,e,f,g.
			a12 = BitOperations.RotateLeft(d, 12);
			uint fgRound37 = e ^ f;
			a12K = a12 + 0x50F3B14FU;
			g += Unsafe.Add(ref words, 12);
			c += Unsafe.Add(ref words, 21);
			ss1 = BitOperations.RotateLeft(h + a12K, 7);
			uint tt2Round37 = g + (fgRound37 & h ^ f) + ss1;
			g = tt2Round37 ^ BitOperations.RotateLeft(tt2Round37, 9) ^ BitOperations.RotateLeft(tt2Round37, 17);
			c = c + (d & (a | b) | a & b) + (ss1 ^ a12);
			a = BitOperations.RotateLeft(a, 9);
			e = BitOperations.RotateLeft(e, 19);
			p1Temp = partial ^ Ssse3.Shuffle(partial.AsByte(), rol8Mask).AsUInt32();
			v4 = partial ^ (Avx512F.VL.IsSupported ? Avx512F.VL.RotateLeft(p1Temp, 15) : p1Temp << 15 | p1Temp >>> 17);
			// Round 38; A..D = c,d,a,b, E..H = g,h,e,f.
			a12 = BitOperations.RotateLeft(c, 12);
			uint fgRound38 = h ^ e;
			a12K = a12 + 0xA1E7629EU;
			f += Unsafe.Add(ref words, 13);
			b += Unsafe.Add(ref words, 22);
			ss1 = BitOperations.RotateLeft(g + a12K, 7);
			uint tt2Round38 = f + (fgRound38 & g ^ e) + ss1;
			f = tt2Round38 ^ BitOperations.RotateLeft(tt2Round38, 9) ^ BitOperations.RotateLeft(tt2Round38, 17);
			b = b + (c & (d | a) | d & a) + (ss1 ^ a12);
			d = BitOperations.RotateLeft(d, 9);
			h = BitOperations.RotateLeft(h, 19);
			v4 ^= (Avx512F.VL.IsSupported ? Avx512F.VL.RotateLeft(window13, 7) : window13 << 7 | window13 >>> 25) ^ v2;
			// Produced W[46..48]; only still-needed scalar operands are stored.
			v4.StoreUnsafe(ref words, 8);
			(Ssse3.AlignRight(v3, Sse2.Shuffle(v2, 0xBF), 12) ^ v4).StoreUnsafe(ref words, 20);

			// Rounds 39..41 also compute W[49..51] from v5,v0,v1,v2,v3,v4, the words before them three at a time, oldest first.
			partial = Ssse3.AlignRight(v0, Sse2.Shuffle(v5, 0xBF), 12);
			// Round 39; A..D = b,c,d,a, E..H = f,g,h,e.
			a12 = BitOperations.RotateLeft(b, 12);
			uint fgRound39 = g ^ h;
			a12K = a12 + 0x43CEC53DU;
			e += Unsafe.Add(ref words, 14);
			a += Unsafe.Add(ref words, 16);
			ss1 = BitOperations.RotateLeft(f + a12K, 7);
			uint tt2Round39 = e + (fgRound39 & f ^ h) + ss1;
			e = tt2Round39 ^ BitOperations.RotateLeft(tt2Round39, 9) ^ BitOperations.RotateLeft(tt2Round39, 17);
			a = a + (b & (c | d) | c & d) + (ss1 ^ a12);
			c = BitOperations.RotateLeft(c, 9);
			g = BitOperations.RotateLeft(g, 19);
			partial ^= v2 ^ (Avx512F.VL.IsSupported ? Avx512F.VL.RotateLeft(v4, 15) : v4 << 15 | v4 >>> 17);
			window13 = Ssse3.AlignRight(v1, Sse2.Shuffle(v0, 0xBF), 12);
			// Round 40; A..D = a,b,c,d, E..H = e,f,g,h.
			a12 = BitOperations.RotateLeft(a, 12);
			uint fgRound40 = f ^ g;
			a12K = a12 + 0x879D8A7AU;
			h += Unsafe.Add(ref words, 0);
			d += Unsafe.Add(ref words, 17);
			ss1 = BitOperations.RotateLeft(e + a12K, 7);
			uint tt2Round40 = h + (fgRound40 & e ^ g) + ss1;
			h = tt2Round40 ^ BitOperations.RotateLeft(tt2Round40, 9) ^ BitOperations.RotateLeft(tt2Round40, 17);
			d = d + (a & (b | c) | b & c) + (ss1 ^ a12);
			b = BitOperations.RotateLeft(b, 9);
			f = BitOperations.RotateLeft(f, 19);
			p1Temp = partial ^ Ssse3.Shuffle(partial.AsByte(), rol8Mask).AsUInt32();
			v5 = partial ^ (Avx512F.VL.IsSupported ? Avx512F.VL.RotateLeft(p1Temp, 15) : p1Temp << 15 | p1Temp >>> 17);
			// Round 41; A..D = d,a,b,c, E..H = h,e,f,g.
			a12 = BitOperations.RotateLeft(d, 12);
			uint fgRound41 = e ^ f;
			a12K = a12 + 0x0F3B14F5U;
			g += Unsafe.Add(ref words, 1);
			c += Unsafe.Add(ref words, 18);
			ss1 = BitOperations.RotateLeft(h + a12K, 7);
			uint tt2Round41 = g + (fgRound41 & h ^ f) + ss1;
			g = tt2Round41 ^ BitOperations.RotateLeft(tt2Round41, 9) ^ BitOperations.RotateLeft(tt2Round41, 17);
			c = c + (d & (a | b) | a & b) + (ss1 ^ a12);
			a = BitOperations.RotateLeft(a, 9);
			e = BitOperations.RotateLeft(e, 19);
			v5 ^= (Avx512F.VL.IsSupported ? Avx512F.VL.RotateLeft(window13, 7) : window13 << 7 | window13 >>> 25) ^ v3;
			// Produced W[49..51]; only still-needed scalar operands are stored.
			v5.StoreUnsafe(ref words, 12);
			(Ssse3.AlignRight(v4, Sse2.Shuffle(v3, 0xBF), 12) ^ v5).StoreUnsafe(ref words, 16);

			// Rounds 42..44 also compute W[52..54] from v0,v1,v2,v3,v4,v5, the words before them three at a time, oldest first.
			partial = Ssse3.AlignRight(v1, Sse2.Shuffle(v0, 0xBF), 12);
			// Round 42; A..D = c,d,a,b, E..H = g,h,e,f.
			a12 = BitOperations.RotateLeft(c, 12);
			uint fgRound42 = h ^ e;
			a12K = a12 + 0x1E7629EAU;
			f += Unsafe.Add(ref words, 2);
			b += Unsafe.Add(ref words, 20);
			ss1 = BitOperations.RotateLeft(g + a12K, 7);
			uint tt2Round42 = f + (fgRound42 & g ^ e) + ss1;
			f = tt2Round42 ^ BitOperations.RotateLeft(tt2Round42, 9) ^ BitOperations.RotateLeft(tt2Round42, 17);
			b = b + (c & (d | a) | d & a) + (ss1 ^ a12);
			d = BitOperations.RotateLeft(d, 9);
			h = BitOperations.RotateLeft(h, 19);
			partial ^= v3 ^ (Avx512F.VL.IsSupported ? Avx512F.VL.RotateLeft(v5, 15) : v5 << 15 | v5 >>> 17);
			window13 = Ssse3.AlignRight(v2, Sse2.Shuffle(v1, 0xBF), 12);
			// Round 43; A..D = b,c,d,a, E..H = f,g,h,e.
			a12 = BitOperations.RotateLeft(b, 12);
			uint fgRound43 = g ^ h;
			a12K = a12 + 0x3CEC53D4U;
			e += Unsafe.Add(ref words, 4);
			a += Unsafe.Add(ref words, 21);
			ss1 = BitOperations.RotateLeft(f + a12K, 7);
			uint tt2Round43 = e + (fgRound43 & f ^ h) + ss1;
			e = tt2Round43 ^ BitOperations.RotateLeft(tt2Round43, 9) ^ BitOperations.RotateLeft(tt2Round43, 17);
			a = a + (b & (c | d) | c & d) + (ss1 ^ a12);
			c = BitOperations.RotateLeft(c, 9);
			g = BitOperations.RotateLeft(g, 19);
			p1Temp = partial ^ Ssse3.Shuffle(partial.AsByte(), rol8Mask).AsUInt32();
			v0 = partial ^ (Avx512F.VL.IsSupported ? Avx512F.VL.RotateLeft(p1Temp, 15) : p1Temp << 15 | p1Temp >>> 17);
			// Round 44; A..D = a,b,c,d, E..H = e,f,g,h.
			a12 = BitOperations.RotateLeft(a, 12);
			uint fgRound44 = f ^ g;
			a12K = a12 + 0x79D8A7A8U;
			h += Unsafe.Add(ref words, 5);
			d += Unsafe.Add(ref words, 22);
			ss1 = BitOperations.RotateLeft(e + a12K, 7);
			uint tt2Round44 = h + (fgRound44 & e ^ g) + ss1;
			h = tt2Round44 ^ BitOperations.RotateLeft(tt2Round44, 9) ^ BitOperations.RotateLeft(tt2Round44, 17);
			d = d + (a & (b | c) | b & c) + (ss1 ^ a12);
			b = BitOperations.RotateLeft(b, 9);
			f = BitOperations.RotateLeft(f, 19);
			v0 ^= (Avx512F.VL.IsSupported ? Avx512F.VL.RotateLeft(window13, 7) : window13 << 7 | window13 >>> 25) ^ v4;
			// Produced W[52..54]; only still-needed scalar operands are stored.
			v0.StoreUnsafe(ref words, 0);
			(Ssse3.AlignRight(v5, Sse2.Shuffle(v4, 0xBF), 12) ^ v0).StoreUnsafe(ref words, 20);

			// Rounds 45..47 also compute W[55..57] from v1,v2,v3,v4,v5,v0, the words before them three at a time, oldest first.
			partial = Ssse3.AlignRight(v2, Sse2.Shuffle(v1, 0xBF), 12);
			// Round 45; A..D = d,a,b,c, E..H = h,e,f,g.
			a12 = BitOperations.RotateLeft(d, 12);
			uint fgRound45 = e ^ f;
			a12K = a12 + 0xF3B14F50U;
			g += Unsafe.Add(ref words, 6);
			c += Unsafe.Add(ref words, 16);
			ss1 = BitOperations.RotateLeft(h + a12K, 7);
			uint tt2Round45 = g + (fgRound45 & h ^ f) + ss1;
			g = tt2Round45 ^ BitOperations.RotateLeft(tt2Round45, 9) ^ BitOperations.RotateLeft(tt2Round45, 17);
			c = c + (d & (a | b) | a & b) + (ss1 ^ a12);
			a = BitOperations.RotateLeft(a, 9);
			e = BitOperations.RotateLeft(e, 19);
			partial ^= v4 ^ (Avx512F.VL.IsSupported ? Avx512F.VL.RotateLeft(v0, 15) : v0 << 15 | v0 >>> 17);
			window13 = Ssse3.AlignRight(v3, Sse2.Shuffle(v2, 0xBF), 12);
			// Round 46; A..D = c,d,a,b, E..H = g,h,e,f.
			a12 = BitOperations.RotateLeft(c, 12);
			uint fgRound46 = h ^ e;
			a12K = a12 + 0xE7629EA1U;
			f += Unsafe.Add(ref words, 8);
			b += Unsafe.Add(ref words, 17);
			ss1 = BitOperations.RotateLeft(g + a12K, 7);
			uint tt2Round46 = f + (fgRound46 & g ^ e) + ss1;
			f = tt2Round46 ^ BitOperations.RotateLeft(tt2Round46, 9) ^ BitOperations.RotateLeft(tt2Round46, 17);
			b = b + (c & (d | a) | d & a) + (ss1 ^ a12);
			d = BitOperations.RotateLeft(d, 9);
			h = BitOperations.RotateLeft(h, 19);
			p1Temp = partial ^ Ssse3.Shuffle(partial.AsByte(), rol8Mask).AsUInt32();
			v1 = partial ^ (Avx512F.VL.IsSupported ? Avx512F.VL.RotateLeft(p1Temp, 15) : p1Temp << 15 | p1Temp >>> 17);
			// Round 47; A..D = b,c,d,a, E..H = f,g,h,e.
			a12 = BitOperations.RotateLeft(b, 12);
			uint fgRound47 = g ^ h;
			a12K = a12 + 0xCEC53D43U;
			e += Unsafe.Add(ref words, 9);
			a += Unsafe.Add(ref words, 18);
			ss1 = BitOperations.RotateLeft(f + a12K, 7);
			uint tt2Round47 = e + (fgRound47 & f ^ h) + ss1;
			e = tt2Round47 ^ BitOperations.RotateLeft(tt2Round47, 9) ^ BitOperations.RotateLeft(tt2Round47, 17);
			a = a + (b & (c | d) | c & d) + (ss1 ^ a12);
			c = BitOperations.RotateLeft(c, 9);
			g = BitOperations.RotateLeft(g, 19);
			v1 ^= (Avx512F.VL.IsSupported ? Avx512F.VL.RotateLeft(window13, 7) : window13 << 7 | window13 >>> 25) ^ v5;
			// Produced W[55..57]; only still-needed scalar operands are stored.
			v1.StoreUnsafe(ref words, 4);
			(Ssse3.AlignRight(v0, Sse2.Shuffle(v5, 0xBF), 12) ^ v1).StoreUnsafe(ref words, 16);

			// Rounds 48..50 also compute W[58..60] from v2,v3,v4,v5,v0,v1, the words before them three at a time, oldest first.
			partial = Ssse3.AlignRight(v3, Sse2.Shuffle(v2, 0xBF), 12);
			// Round 48; A..D = a,b,c,d, E..H = e,f,g,h.
			a12 = BitOperations.RotateLeft(a, 12);
			uint fgRound48 = f ^ g;
			a12K = a12 + 0x9D8A7A87U;
			h += Unsafe.Add(ref words, 10);
			d += Unsafe.Add(ref words, 20);
			ss1 = BitOperations.RotateLeft(e + a12K, 7);
			uint tt2Round48 = h + (fgRound48 & e ^ g) + ss1;
			h = tt2Round48 ^ BitOperations.RotateLeft(tt2Round48, 9) ^ BitOperations.RotateLeft(tt2Round48, 17);
			d = d + (a & (b | c) | b & c) + (ss1 ^ a12);
			b = BitOperations.RotateLeft(b, 9);
			f = BitOperations.RotateLeft(f, 19);
			partial ^= v5 ^ (Avx512F.VL.IsSupported ? Avx512F.VL.RotateLeft(v1, 15) : v1 << 15 | v1 >>> 17);
			window13 = Ssse3.AlignRight(v4, Sse2.Shuffle(v3, 0xBF), 12);
			// Round 49; A..D = d,a,b,c, E..H = h,e,f,g.
			a12 = BitOperations.RotateLeft(d, 12);
			uint fgRound49 = e ^ f;
			a12K = a12 + 0x3B14F50FU;
			g += Unsafe.Add(ref words, 12);
			c += Unsafe.Add(ref words, 21);
			ss1 = BitOperations.RotateLeft(h + a12K, 7);
			uint tt2Round49 = g + (fgRound49 & h ^ f) + ss1;
			g = tt2Round49 ^ BitOperations.RotateLeft(tt2Round49, 9) ^ BitOperations.RotateLeft(tt2Round49, 17);
			c = c + (d & (a | b) | a & b) + (ss1 ^ a12);
			a = BitOperations.RotateLeft(a, 9);
			e = BitOperations.RotateLeft(e, 19);
			p1Temp = partial ^ Ssse3.Shuffle(partial.AsByte(), rol8Mask).AsUInt32();
			v2 = partial ^ (Avx512F.VL.IsSupported ? Avx512F.VL.RotateLeft(p1Temp, 15) : p1Temp << 15 | p1Temp >>> 17);
			// Round 50; A..D = c,d,a,b, E..H = g,h,e,f.
			a12 = BitOperations.RotateLeft(c, 12);
			uint fgRound50 = h ^ e;
			a12K = a12 + 0x7629EA1EU;
			f += Unsafe.Add(ref words, 13);
			b += Unsafe.Add(ref words, 22);
			ss1 = BitOperations.RotateLeft(g + a12K, 7);
			uint tt2Round50 = f + (fgRound50 & g ^ e) + ss1;
			f = tt2Round50 ^ BitOperations.RotateLeft(tt2Round50, 9) ^ BitOperations.RotateLeft(tt2Round50, 17);
			b = b + (c & (d | a) | d & a) + (ss1 ^ a12);
			d = BitOperations.RotateLeft(d, 9);
			h = BitOperations.RotateLeft(h, 19);
			v2 ^= (Avx512F.VL.IsSupported ? Avx512F.VL.RotateLeft(window13, 7) : window13 << 7 | window13 >>> 25) ^ v0;
			// Produced W[58..60]; only still-needed scalar operands are stored.
			v2.StoreUnsafe(ref words, 8);
			(Ssse3.AlignRight(v1, Sse2.Shuffle(v0, 0xBF), 12) ^ v2).StoreUnsafe(ref words, 20);

			// Rounds 51..53 also compute W[61..63] from v3,v4,v5,v0,v1,v2, the words before them three at a time, oldest first.
			partial = Ssse3.AlignRight(v4, Sse2.Shuffle(v3, 0xBF), 12);
			// Round 51; A..D = b,c,d,a, E..H = f,g,h,e.
			a12 = BitOperations.RotateLeft(b, 12);
			uint fgRound51 = g ^ h;
			a12K = a12 + 0xEC53D43CU;
			e += Unsafe.Add(ref words, 14);
			a += Unsafe.Add(ref words, 16);
			ss1 = BitOperations.RotateLeft(f + a12K, 7);
			uint tt2Round51 = e + (fgRound51 & f ^ h) + ss1;
			e = tt2Round51 ^ BitOperations.RotateLeft(tt2Round51, 9) ^ BitOperations.RotateLeft(tt2Round51, 17);
			a = a + (b & (c | d) | c & d) + (ss1 ^ a12);
			c = BitOperations.RotateLeft(c, 9);
			g = BitOperations.RotateLeft(g, 19);
			partial ^= v0 ^ (Avx512F.VL.IsSupported ? Avx512F.VL.RotateLeft(v2, 15) : v2 << 15 | v2 >>> 17);
			window13 = Ssse3.AlignRight(v5, Sse2.Shuffle(v4, 0xBF), 12);
			// Round 52; A..D = a,b,c,d, E..H = e,f,g,h.
			a12 = BitOperations.RotateLeft(a, 12);
			uint fgRound52 = f ^ g;
			a12K = a12 + 0xD8A7A879U;
			h += Unsafe.Add(ref words, 0);
			d += Unsafe.Add(ref words, 17);
			ss1 = BitOperations.RotateLeft(e + a12K, 7);
			uint tt2Round52 = h + (fgRound52 & e ^ g) + ss1;
			h = tt2Round52 ^ BitOperations.RotateLeft(tt2Round52, 9) ^ BitOperations.RotateLeft(tt2Round52, 17);
			d = d + (a & (b | c) | b & c) + (ss1 ^ a12);
			b = BitOperations.RotateLeft(b, 9);
			f = BitOperations.RotateLeft(f, 19);
			p1Temp = partial ^ Ssse3.Shuffle(partial.AsByte(), rol8Mask).AsUInt32();
			v3 = partial ^ (Avx512F.VL.IsSupported ? Avx512F.VL.RotateLeft(p1Temp, 15) : p1Temp << 15 | p1Temp >>> 17);
			// Round 53; A..D = d,a,b,c, E..H = h,e,f,g.
			a12 = BitOperations.RotateLeft(d, 12);
			uint fgRound53 = e ^ f;
			a12K = a12 + 0xB14F50F3U;
			g += Unsafe.Add(ref words, 1);
			c += Unsafe.Add(ref words, 18);
			ss1 = BitOperations.RotateLeft(h + a12K, 7);
			uint tt2Round53 = g + (fgRound53 & h ^ f) + ss1;
			g = tt2Round53 ^ BitOperations.RotateLeft(tt2Round53, 9) ^ BitOperations.RotateLeft(tt2Round53, 17);
			c = c + (d & (a | b) | a & b) + (ss1 ^ a12);
			a = BitOperations.RotateLeft(a, 9);
			e = BitOperations.RotateLeft(e, 19);
			v3 ^= (Avx512F.VL.IsSupported ? Avx512F.VL.RotateLeft(window13, 7) : window13 << 7 | window13 >>> 25) ^ v1;
			// Produced W[61..63]; only still-needed scalar operands are stored.
			v3.StoreUnsafe(ref words, 12);
			(Ssse3.AlignRight(v2, Sse2.Shuffle(v1, 0xBF), 12) ^ v3).StoreUnsafe(ref words, 16);

			// Rounds 54..56 also compute W[64..66] from v4,v5,v0,v1,v2,v3, the words before them three at a time, oldest first.
			partial = Ssse3.AlignRight(v5, Sse2.Shuffle(v4, 0xBF), 12);
			// Round 54; A..D = c,d,a,b, E..H = g,h,e,f.
			a12 = BitOperations.RotateLeft(c, 12);
			uint fgRound54 = h ^ e;
			a12K = a12 + 0x629EA1E7U;
			f += Unsafe.Add(ref words, 2);
			b += Unsafe.Add(ref words, 20);
			ss1 = BitOperations.RotateLeft(g + a12K, 7);
			uint tt2Round54 = f + (fgRound54 & g ^ e) + ss1;
			f = tt2Round54 ^ BitOperations.RotateLeft(tt2Round54, 9) ^ BitOperations.RotateLeft(tt2Round54, 17);
			b = b + (c & (d | a) | d & a) + (ss1 ^ a12);
			d = BitOperations.RotateLeft(d, 9);
			h = BitOperations.RotateLeft(h, 19);
			partial ^= v1 ^ (Avx512F.VL.IsSupported ? Avx512F.VL.RotateLeft(v3, 15) : v3 << 15 | v3 >>> 17);
			window13 = Ssse3.AlignRight(v0, Sse2.Shuffle(v5, 0xBF), 12);
			// Round 55; A..D = b,c,d,a, E..H = f,g,h,e.
			a12 = BitOperations.RotateLeft(b, 12);
			uint fgRound55 = g ^ h;
			a12K = a12 + 0xC53D43CEU;
			e += Unsafe.Add(ref words, 4);
			a += Unsafe.Add(ref words, 21);
			ss1 = BitOperations.RotateLeft(f + a12K, 7);
			uint tt2Round55 = e + (fgRound55 & f ^ h) + ss1;
			e = tt2Round55 ^ BitOperations.RotateLeft(tt2Round55, 9) ^ BitOperations.RotateLeft(tt2Round55, 17);
			a = a + (b & (c | d) | c & d) + (ss1 ^ a12);
			c = BitOperations.RotateLeft(c, 9);
			g = BitOperations.RotateLeft(g, 19);
			p1Temp = partial ^ Ssse3.Shuffle(partial.AsByte(), rol8Mask).AsUInt32();
			v4 = partial ^ (Avx512F.VL.IsSupported ? Avx512F.VL.RotateLeft(p1Temp, 15) : p1Temp << 15 | p1Temp >>> 17);
			// Round 56; A..D = a,b,c,d, E..H = e,f,g,h.
			a12 = BitOperations.RotateLeft(a, 12);
			uint fgRound56 = f ^ g;
			a12K = a12 + 0x8A7A879DU;
			h += Unsafe.Add(ref words, 5);
			d += Unsafe.Add(ref words, 22);
			ss1 = BitOperations.RotateLeft(e + a12K, 7);
			uint tt2Round56 = h + (fgRound56 & e ^ g) + ss1;
			h = tt2Round56 ^ BitOperations.RotateLeft(tt2Round56, 9) ^ BitOperations.RotateLeft(tt2Round56, 17);
			d = d + (a & (b | c) | b & c) + (ss1 ^ a12);
			b = BitOperations.RotateLeft(b, 9);
			f = BitOperations.RotateLeft(f, 19);
			v4 ^= (Avx512F.VL.IsSupported ? Avx512F.VL.RotateLeft(window13, 7) : window13 << 7 | window13 >>> 25) ^ v2;
			// Produced W[64..66]; only still-needed scalar operands are stored.
			(Ssse3.AlignRight(v3, Sse2.Shuffle(v2, 0xBF), 12) ^ v4).StoreUnsafe(ref words, 20);

			// Rounds 57..59 also compute W[67..69] from v5,v0,v1,v2,v3,v4, the words before them three at a time, oldest first.
			partial = Ssse3.AlignRight(v0, Sse2.Shuffle(v5, 0xBF), 12);
			// Round 57; A..D = d,a,b,c, E..H = h,e,f,g.
			a12 = BitOperations.RotateLeft(d, 12);
			uint fgRound57 = e ^ f;
			a12K = a12 + 0x14F50F3BU;
			g += Unsafe.Add(ref words, 6);
			c += Unsafe.Add(ref words, 16);
			ss1 = BitOperations.RotateLeft(h + a12K, 7);
			uint tt2Round57 = g + (fgRound57 & h ^ f) + ss1;
			g = tt2Round57 ^ BitOperations.RotateLeft(tt2Round57, 9) ^ BitOperations.RotateLeft(tt2Round57, 17);
			c = c + (d & (a | b) | a & b) + (ss1 ^ a12);
			a = BitOperations.RotateLeft(a, 9);
			e = BitOperations.RotateLeft(e, 19);
			partial ^= v2 ^ (Avx512F.VL.IsSupported ? Avx512F.VL.RotateLeft(v4, 15) : v4 << 15 | v4 >>> 17);
			window13 = Ssse3.AlignRight(v1, Sse2.Shuffle(v0, 0xBF), 12);
			// Round 58; A..D = c,d,a,b, E..H = g,h,e,f.
			a12 = BitOperations.RotateLeft(c, 12);
			uint fgRound58 = h ^ e;
			a12K = a12 + 0x29EA1E76U;
			f += Unsafe.Add(ref words, 8);
			b += Unsafe.Add(ref words, 17);
			ss1 = BitOperations.RotateLeft(g + a12K, 7);
			uint tt2Round58 = f + (fgRound58 & g ^ e) + ss1;
			f = tt2Round58 ^ BitOperations.RotateLeft(tt2Round58, 9) ^ BitOperations.RotateLeft(tt2Round58, 17);
			b = b + (c & (d | a) | d & a) + (ss1 ^ a12);
			d = BitOperations.RotateLeft(d, 9);
			h = BitOperations.RotateLeft(h, 19);
			p1Temp = partial ^ Ssse3.Shuffle(partial.AsByte(), rol8Mask).AsUInt32();
			v5 = partial ^ (Avx512F.VL.IsSupported ? Avx512F.VL.RotateLeft(p1Temp, 15) : p1Temp << 15 | p1Temp >>> 17);
			// Round 59; A..D = b,c,d,a, E..H = f,g,h,e.
			a12 = BitOperations.RotateLeft(b, 12);
			uint fgRound59 = g ^ h;
			a12K = a12 + 0x53D43CECU;
			e += Unsafe.Add(ref words, 9);
			a += Unsafe.Add(ref words, 18);
			ss1 = BitOperations.RotateLeft(f + a12K, 7);
			uint tt2Round59 = e + (fgRound59 & f ^ h) + ss1;
			e = tt2Round59 ^ BitOperations.RotateLeft(tt2Round59, 9) ^ BitOperations.RotateLeft(tt2Round59, 17);
			a = a + (b & (c | d) | c & d) + (ss1 ^ a12);
			c = BitOperations.RotateLeft(c, 9);
			g = BitOperations.RotateLeft(g, 19);
			v5 ^= (Avx512F.VL.IsSupported ? Avx512F.VL.RotateLeft(window13, 7) : window13 << 7 | window13 >>> 25) ^ v3;
			// Produced W[67..69]; only still-needed scalar operands are stored.
			Unsafe.Add(ref words, 16) = Unsafe.Add(ref words, 14) ^ v5.ToScalar();

			// Round 60; A..D = a,b,c,d, E..H = e,f,g,h.
			a12 = BitOperations.RotateLeft(a, 12);
			uint fgRound60 = f ^ g;
			a12K = a12 + 0xA7A879D8U;
			h += Unsafe.Add(ref words, 10);
			d += Unsafe.Add(ref words, 20);
			ss1 = BitOperations.RotateLeft(e + a12K, 7);
			uint tt2Round60 = h + (fgRound60 & e ^ g) + ss1;
			h = tt2Round60 ^ BitOperations.RotateLeft(tt2Round60, 9) ^ BitOperations.RotateLeft(tt2Round60, 17);
			d = d + (a & (b | c) | b & c) + (ss1 ^ a12);
			b = BitOperations.RotateLeft(b, 9);
			f = BitOperations.RotateLeft(f, 19);
			// Round 61; A..D = d,a,b,c, E..H = h,e,f,g.
			a12 = BitOperations.RotateLeft(d, 12);
			uint fgRound61 = e ^ f;
			a12K = a12 + 0x4F50F3B1U;
			g += Unsafe.Add(ref words, 12);
			c += Unsafe.Add(ref words, 21);
			ss1 = BitOperations.RotateLeft(h + a12K, 7);
			uint tt2Round61 = g + (fgRound61 & h ^ f) + ss1;
			g = tt2Round61 ^ BitOperations.RotateLeft(tt2Round61, 9) ^ BitOperations.RotateLeft(tt2Round61, 17);
			c = c + (d & (a | b) | a & b) + (ss1 ^ a12);
			a = BitOperations.RotateLeft(a, 9);
			e = BitOperations.RotateLeft(e, 19);
			// Round 62; A..D = c,d,a,b, E..H = g,h,e,f.
			a12 = BitOperations.RotateLeft(c, 12);
			uint fgRound62 = h ^ e;
			a12K = a12 + 0x9EA1E762U;
			f += Unsafe.Add(ref words, 13);
			b += Unsafe.Add(ref words, 22);
			ss1 = BitOperations.RotateLeft(g + a12K, 7);
			uint tt2Round62 = f + (fgRound62 & g ^ e) + ss1;
			f = tt2Round62 ^ BitOperations.RotateLeft(tt2Round62, 9) ^ BitOperations.RotateLeft(tt2Round62, 17);
			b = b + (c & (d | a) | d & a) + (ss1 ^ a12);
			d = BitOperations.RotateLeft(d, 9);
			h = BitOperations.RotateLeft(h, 19);
			// Round 63; A..D = b,c,d,a, E..H = f,g,h,e.
			a12 = BitOperations.RotateLeft(b, 12);
			uint fgRound63 = g ^ h;
			a12K = a12 + 0x3D43CEC5U;
			e += Unsafe.Add(ref words, 14);
			a += Unsafe.Add(ref words, 16);
			ss1 = BitOperations.RotateLeft(f + a12K, 7);
			uint tt2Round63 = e + (fgRound63 & f ^ h) + ss1;
			e = tt2Round63 ^ BitOperations.RotateLeft(tt2Round63, 9) ^ BitOperations.RotateLeft(tt2Round63, 17);
			a = a + (b & (c | d) | c & d) + (ss1 ^ a12);
			c = BitOperations.RotateLeft(c, 9);
			g = BitOperations.RotateLeft(g, 19);

			hashAlgorithm._v0 = a ^= hashAlgorithm._v0;
			hashAlgorithm._v1 = b ^= hashAlgorithm._v1;
			hashAlgorithm._v2 = c ^= hashAlgorithm._v2;
			hashAlgorithm._v3 = d ^= hashAlgorithm._v3;
			hashAlgorithm._v4 = e ^= hashAlgorithm._v4;
			hashAlgorithm._v5 = f ^= hashAlgorithm._v5;
			hashAlgorithm._v6 = g ^= hashAlgorithm._v6;
			hashAlgorithm._v7 = h ^= hashAlgorithm._v7;
			block0 = ref Unsafe.Add(ref block0, BlockSizeInBytes);
			remaining -= BlockSizeInBytes;
		} while (remaining is not 0);
	}
}
