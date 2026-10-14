namespace CryptoBase.Kdf.Argon2;

internal readonly struct Argon2Vector256 : IArgon2Kernel
{
	public static bool IsSupported => Avx2.IsSupported;

	[MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.AggressiveOptimization)]
	public static void Compress(ref Argon2Block previous, ref Argon2Block reference, ref Argon2Block destination, ref Argon2Block scratch, bool xorDestination)
	{
		Debug.Assert(IsSupported);

		if (Avx512F.VL.IsSupported)
		{
			CompressFourRows(ref previous, ref reference, ref destination, ref scratch, xorDestination);
			return;
		}

		ref ulong x = ref previous[0];
		ref ulong y = ref reference[0];
		ref ulong state = ref destination[0];
		ref ulong final = ref scratch[0];

		for (nuint offset = 0; offset < Argon2Block.QWordCount; offset += 32)
		{
			Vector256<ulong> a0 = Vector256.LoadUnsafe(ref x, offset) ^ Vector256.LoadUnsafe(ref y, offset);
			Vector256<ulong> b0 = Vector256.LoadUnsafe(ref x, offset + 4) ^ Vector256.LoadUnsafe(ref y, offset + 4);
			Vector256<ulong> c0 = Vector256.LoadUnsafe(ref x, offset + 8) ^ Vector256.LoadUnsafe(ref y, offset + 8);
			Vector256<ulong> d0 = Vector256.LoadUnsafe(ref x, offset + 12) ^ Vector256.LoadUnsafe(ref y, offset + 12);
			Vector256<ulong> a1 = Vector256.LoadUnsafe(ref x, offset + 16) ^ Vector256.LoadUnsafe(ref y, offset + 16);
			Vector256<ulong> b1 = Vector256.LoadUnsafe(ref x, offset + 20) ^ Vector256.LoadUnsafe(ref y, offset + 20);
			Vector256<ulong> c1 = Vector256.LoadUnsafe(ref x, offset + 24) ^ Vector256.LoadUnsafe(ref y, offset + 24);
			Vector256<ulong> d1 = Vector256.LoadUnsafe(ref x, offset + 28) ^ Vector256.LoadUnsafe(ref y, offset + 28);

			if (xorDestination)
			{
				(a0 ^ Vector256.LoadUnsafe(ref state, offset)).StoreUnsafe(ref final, offset);
				(b0 ^ Vector256.LoadUnsafe(ref state, offset + 4)).StoreUnsafe(ref final, offset + 4);
				(c0 ^ Vector256.LoadUnsafe(ref state, offset + 8)).StoreUnsafe(ref final, offset + 8);
				(d0 ^ Vector256.LoadUnsafe(ref state, offset + 12)).StoreUnsafe(ref final, offset + 12);
				(a1 ^ Vector256.LoadUnsafe(ref state, offset + 16)).StoreUnsafe(ref final, offset + 16);
				(b1 ^ Vector256.LoadUnsafe(ref state, offset + 20)).StoreUnsafe(ref final, offset + 20);
				(c1 ^ Vector256.LoadUnsafe(ref state, offset + 24)).StoreUnsafe(ref final, offset + 24);
				(d1 ^ Vector256.LoadUnsafe(ref state, offset + 28)).StoreUnsafe(ref final, offset + 28);
			}
			else
			{
				a0.StoreUnsafe(ref final, offset);
				b0.StoreUnsafe(ref final, offset + 4);
				c0.StoreUnsafe(ref final, offset + 8);
				d0.StoreUnsafe(ref final, offset + 12);
				a1.StoreUnsafe(ref final, offset + 16);
				b1.StoreUnsafe(ref final, offset + 20);
				c1.StoreUnsafe(ref final, offset + 24);
				d1.StoreUnsafe(ref final, offset + 28);
			}

			G(ref a0, ref a1, ref b0, ref b1, ref c0, ref c1, ref d0, ref d1);

			// Diagonalizing a, c and d leaves b, which G finishes last, off the permutation path.
			a0 = Avx2.Permute4x64(a0, 0b10_01_00_11);
			a1 = Avx2.Permute4x64(a1, 0b10_01_00_11);
			c0 = Avx2.Permute4x64(c0, 0b00_11_10_01);
			c1 = Avx2.Permute4x64(c1, 0b00_11_10_01);
			d0 = Avx2.Permute4x64(d0, 0b01_00_11_10);
			d1 = Avx2.Permute4x64(d1, 0b01_00_11_10);

			G(ref a0, ref a1, ref b0, ref b1, ref c0, ref c1, ref d0, ref d1);

			a0 = Avx2.Permute4x64(a0, 0b00_11_10_01);
			a1 = Avx2.Permute4x64(a1, 0b00_11_10_01);
			c0 = Avx2.Permute4x64(c0, 0b10_01_00_11);
			c1 = Avx2.Permute4x64(c1, 0b10_01_00_11);
			d0 = Avx2.Permute4x64(d0, 0b01_00_11_10);
			d1 = Avx2.Permute4x64(d1, 0b01_00_11_10);

			a0.StoreUnsafe(ref state, offset);
			b0.StoreUnsafe(ref state, offset + 4);
			c0.StoreUnsafe(ref state, offset + 8);
			d0.StoreUnsafe(ref state, offset + 12);
			a1.StoreUnsafe(ref state, offset + 16);
			b1.StoreUnsafe(ref state, offset + 20);
			c1.StoreUnsafe(ref state, offset + 24);
			d1.StoreUnsafe(ref state, offset + 28);
		}

		// Two columns per iteration: each 128-bit lane holds one column, so diagonalizing stays within lanes.
		for (nuint offset = 0; offset < 16; offset += 4)
		{
			Vector256<ulong> a0 = Vector256.LoadUnsafe(ref state, offset);
			Vector256<ulong> a1 = Vector256.LoadUnsafe(ref state, offset + 16);
			Vector256<ulong> b0 = Vector256.LoadUnsafe(ref state, offset + 32);
			Vector256<ulong> b1 = Vector256.LoadUnsafe(ref state, offset + 48);
			Vector256<ulong> c0 = Vector256.LoadUnsafe(ref state, offset + 64);
			Vector256<ulong> c1 = Vector256.LoadUnsafe(ref state, offset + 80);
			Vector256<ulong> d0 = Vector256.LoadUnsafe(ref state, offset + 96);
			Vector256<ulong> d1 = Vector256.LoadUnsafe(ref state, offset + 112);

			G(ref a0, ref a1, ref b0, ref b1, ref c0, ref c1, ref d0, ref d1);

			Vector256<ulong> rotatedA0 = Concat(a1, a0);
			Vector256<ulong> rotatedA1 = Concat(a0, a1);
			Vector256<ulong> rotatedC0 = Concat(c0, c1);
			Vector256<ulong> rotatedC1 = Concat(c1, c0);

			G(ref rotatedA0, ref rotatedA1, ref b0, ref b1, ref rotatedC0, ref rotatedC1, ref d1, ref d0);

			a0 = Concat(rotatedA0, rotatedA1);
			a1 = Concat(rotatedA1, rotatedA0);
			c0 = Concat(rotatedC1, rotatedC0);
			c1 = Concat(rotatedC0, rotatedC1);

			(a0 ^ Vector256.LoadUnsafe(ref final, offset)).StoreUnsafe(ref state, offset);
			(a1 ^ Vector256.LoadUnsafe(ref final, offset + 16)).StoreUnsafe(ref state, offset + 16);
			(b0 ^ Vector256.LoadUnsafe(ref final, offset + 32)).StoreUnsafe(ref state, offset + 32);
			(b1 ^ Vector256.LoadUnsafe(ref final, offset + 48)).StoreUnsafe(ref state, offset + 48);
			(c0 ^ Vector256.LoadUnsafe(ref final, offset + 64)).StoreUnsafe(ref state, offset + 64);
			(c1 ^ Vector256.LoadUnsafe(ref final, offset + 80)).StoreUnsafe(ref state, offset + 80);
			(d0 ^ Vector256.LoadUnsafe(ref final, offset + 96)).StoreUnsafe(ref state, offset + 96);
			(d1 ^ Vector256.LoadUnsafe(ref final, offset + 112)).StoreUnsafe(ref state, offset + 112);
		}
	}

	// With AVX-512VL, the 32 YMM registers hold four rows or columns, so each iteration runs four independent chains through G instead of the two of Compress, hiding more of the multiply and rotate latency; the 16 registers of AVX2 alone cannot hold the 16 vectors of four rows.
	[MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.AggressiveOptimization)]
	private static void CompressFourRows(ref Argon2Block previous, ref Argon2Block reference, ref Argon2Block destination, ref Argon2Block scratch, bool xorDestination)
	{
		Debug.Assert(Avx512F.VL.IsSupported);

		ref ulong x = ref previous[0];
		ref ulong y = ref reference[0];
		ref ulong state = ref destination[0];
		ref ulong final = ref scratch[0];

		for (nuint offset = 0; offset < Argon2Block.QWordCount; offset += 64)
		{
			Vector256<ulong> a0 = Vector256.LoadUnsafe(ref x, offset) ^ Vector256.LoadUnsafe(ref y, offset);
			Vector256<ulong> b0 = Vector256.LoadUnsafe(ref x, offset + 4) ^ Vector256.LoadUnsafe(ref y, offset + 4);
			Vector256<ulong> c0 = Vector256.LoadUnsafe(ref x, offset + 8) ^ Vector256.LoadUnsafe(ref y, offset + 8);
			Vector256<ulong> d0 = Vector256.LoadUnsafe(ref x, offset + 12) ^ Vector256.LoadUnsafe(ref y, offset + 12);
			Vector256<ulong> a1 = Vector256.LoadUnsafe(ref x, offset + 16) ^ Vector256.LoadUnsafe(ref y, offset + 16);
			Vector256<ulong> b1 = Vector256.LoadUnsafe(ref x, offset + 20) ^ Vector256.LoadUnsafe(ref y, offset + 20);
			Vector256<ulong> c1 = Vector256.LoadUnsafe(ref x, offset + 24) ^ Vector256.LoadUnsafe(ref y, offset + 24);
			Vector256<ulong> d1 = Vector256.LoadUnsafe(ref x, offset + 28) ^ Vector256.LoadUnsafe(ref y, offset + 28);
			Vector256<ulong> a2 = Vector256.LoadUnsafe(ref x, offset + 32) ^ Vector256.LoadUnsafe(ref y, offset + 32);
			Vector256<ulong> b2 = Vector256.LoadUnsafe(ref x, offset + 36) ^ Vector256.LoadUnsafe(ref y, offset + 36);
			Vector256<ulong> c2 = Vector256.LoadUnsafe(ref x, offset + 40) ^ Vector256.LoadUnsafe(ref y, offset + 40);
			Vector256<ulong> d2 = Vector256.LoadUnsafe(ref x, offset + 44) ^ Vector256.LoadUnsafe(ref y, offset + 44);
			Vector256<ulong> a3 = Vector256.LoadUnsafe(ref x, offset + 48) ^ Vector256.LoadUnsafe(ref y, offset + 48);
			Vector256<ulong> b3 = Vector256.LoadUnsafe(ref x, offset + 52) ^ Vector256.LoadUnsafe(ref y, offset + 52);
			Vector256<ulong> c3 = Vector256.LoadUnsafe(ref x, offset + 56) ^ Vector256.LoadUnsafe(ref y, offset + 56);
			Vector256<ulong> d3 = Vector256.LoadUnsafe(ref x, offset + 60) ^ Vector256.LoadUnsafe(ref y, offset + 60);

			if (xorDestination)
			{
				(a0 ^ Vector256.LoadUnsafe(ref state, offset)).StoreUnsafe(ref final, offset);
				(b0 ^ Vector256.LoadUnsafe(ref state, offset + 4)).StoreUnsafe(ref final, offset + 4);
				(c0 ^ Vector256.LoadUnsafe(ref state, offset + 8)).StoreUnsafe(ref final, offset + 8);
				(d0 ^ Vector256.LoadUnsafe(ref state, offset + 12)).StoreUnsafe(ref final, offset + 12);
				(a1 ^ Vector256.LoadUnsafe(ref state, offset + 16)).StoreUnsafe(ref final, offset + 16);
				(b1 ^ Vector256.LoadUnsafe(ref state, offset + 20)).StoreUnsafe(ref final, offset + 20);
				(c1 ^ Vector256.LoadUnsafe(ref state, offset + 24)).StoreUnsafe(ref final, offset + 24);
				(d1 ^ Vector256.LoadUnsafe(ref state, offset + 28)).StoreUnsafe(ref final, offset + 28);
				(a2 ^ Vector256.LoadUnsafe(ref state, offset + 32)).StoreUnsafe(ref final, offset + 32);
				(b2 ^ Vector256.LoadUnsafe(ref state, offset + 36)).StoreUnsafe(ref final, offset + 36);
				(c2 ^ Vector256.LoadUnsafe(ref state, offset + 40)).StoreUnsafe(ref final, offset + 40);
				(d2 ^ Vector256.LoadUnsafe(ref state, offset + 44)).StoreUnsafe(ref final, offset + 44);
				(a3 ^ Vector256.LoadUnsafe(ref state, offset + 48)).StoreUnsafe(ref final, offset + 48);
				(b3 ^ Vector256.LoadUnsafe(ref state, offset + 52)).StoreUnsafe(ref final, offset + 52);
				(c3 ^ Vector256.LoadUnsafe(ref state, offset + 56)).StoreUnsafe(ref final, offset + 56);
				(d3 ^ Vector256.LoadUnsafe(ref state, offset + 60)).StoreUnsafe(ref final, offset + 60);
			}
			else
			{
				a0.StoreUnsafe(ref final, offset);
				b0.StoreUnsafe(ref final, offset + 4);
				c0.StoreUnsafe(ref final, offset + 8);
				d0.StoreUnsafe(ref final, offset + 12);
				a1.StoreUnsafe(ref final, offset + 16);
				b1.StoreUnsafe(ref final, offset + 20);
				c1.StoreUnsafe(ref final, offset + 24);
				d1.StoreUnsafe(ref final, offset + 28);
				a2.StoreUnsafe(ref final, offset + 32);
				b2.StoreUnsafe(ref final, offset + 36);
				c2.StoreUnsafe(ref final, offset + 40);
				d2.StoreUnsafe(ref final, offset + 44);
				a3.StoreUnsafe(ref final, offset + 48);
				b3.StoreUnsafe(ref final, offset + 52);
				c3.StoreUnsafe(ref final, offset + 56);
				d3.StoreUnsafe(ref final, offset + 60);
			}

			G(ref a0, ref a1, ref a2, ref a3, ref b0, ref b1, ref b2, ref b3, ref c0, ref c1, ref c2, ref c3, ref d0, ref d1, ref d2, ref d3);

			a0 = Avx2.Permute4x64(a0, 0b10_01_00_11);
			a1 = Avx2.Permute4x64(a1, 0b10_01_00_11);
			a2 = Avx2.Permute4x64(a2, 0b10_01_00_11);
			a3 = Avx2.Permute4x64(a3, 0b10_01_00_11);
			c0 = Avx2.Permute4x64(c0, 0b00_11_10_01);
			c1 = Avx2.Permute4x64(c1, 0b00_11_10_01);
			c2 = Avx2.Permute4x64(c2, 0b00_11_10_01);
			c3 = Avx2.Permute4x64(c3, 0b00_11_10_01);
			d0 = Avx2.Permute4x64(d0, 0b01_00_11_10);
			d1 = Avx2.Permute4x64(d1, 0b01_00_11_10);
			d2 = Avx2.Permute4x64(d2, 0b01_00_11_10);
			d3 = Avx2.Permute4x64(d3, 0b01_00_11_10);

			G(ref a0, ref a1, ref a2, ref a3, ref b0, ref b1, ref b2, ref b3, ref c0, ref c1, ref c2, ref c3, ref d0, ref d1, ref d2, ref d3);

			a0 = Avx2.Permute4x64(a0, 0b00_11_10_01);
			a1 = Avx2.Permute4x64(a1, 0b00_11_10_01);
			a2 = Avx2.Permute4x64(a2, 0b00_11_10_01);
			a3 = Avx2.Permute4x64(a3, 0b00_11_10_01);
			c0 = Avx2.Permute4x64(c0, 0b10_01_00_11);
			c1 = Avx2.Permute4x64(c1, 0b10_01_00_11);
			c2 = Avx2.Permute4x64(c2, 0b10_01_00_11);
			c3 = Avx2.Permute4x64(c3, 0b10_01_00_11);
			d0 = Avx2.Permute4x64(d0, 0b01_00_11_10);
			d1 = Avx2.Permute4x64(d1, 0b01_00_11_10);
			d2 = Avx2.Permute4x64(d2, 0b01_00_11_10);
			d3 = Avx2.Permute4x64(d3, 0b01_00_11_10);

			a0.StoreUnsafe(ref state, offset);
			b0.StoreUnsafe(ref state, offset + 4);
			c0.StoreUnsafe(ref state, offset + 8);
			d0.StoreUnsafe(ref state, offset + 12);
			a1.StoreUnsafe(ref state, offset + 16);
			b1.StoreUnsafe(ref state, offset + 20);
			c1.StoreUnsafe(ref state, offset + 24);
			d1.StoreUnsafe(ref state, offset + 28);
			a2.StoreUnsafe(ref state, offset + 32);
			b2.StoreUnsafe(ref state, offset + 36);
			c2.StoreUnsafe(ref state, offset + 40);
			d2.StoreUnsafe(ref state, offset + 44);
			a3.StoreUnsafe(ref state, offset + 48);
			b3.StoreUnsafe(ref state, offset + 52);
			c3.StoreUnsafe(ref state, offset + 56);
			d3.StoreUnsafe(ref state, offset + 60);
		}

		for (nuint offset = 0; offset < 16; offset += 8)
		{
			Vector256<ulong> a0 = Vector256.LoadUnsafe(ref state, offset);
			Vector256<ulong> a1 = Vector256.LoadUnsafe(ref state, offset + 16);
			Vector256<ulong> b0 = Vector256.LoadUnsafe(ref state, offset + 32);
			Vector256<ulong> b1 = Vector256.LoadUnsafe(ref state, offset + 48);
			Vector256<ulong> c0 = Vector256.LoadUnsafe(ref state, offset + 64);
			Vector256<ulong> c1 = Vector256.LoadUnsafe(ref state, offset + 80);
			Vector256<ulong> d0 = Vector256.LoadUnsafe(ref state, offset + 96);
			Vector256<ulong> d1 = Vector256.LoadUnsafe(ref state, offset + 112);
			Vector256<ulong> a2 = Vector256.LoadUnsafe(ref state, offset + 4);
			Vector256<ulong> a3 = Vector256.LoadUnsafe(ref state, offset + 20);
			Vector256<ulong> b2 = Vector256.LoadUnsafe(ref state, offset + 36);
			Vector256<ulong> b3 = Vector256.LoadUnsafe(ref state, offset + 52);
			Vector256<ulong> c2 = Vector256.LoadUnsafe(ref state, offset + 68);
			Vector256<ulong> c3 = Vector256.LoadUnsafe(ref state, offset + 84);
			Vector256<ulong> d2 = Vector256.LoadUnsafe(ref state, offset + 100);
			Vector256<ulong> d3 = Vector256.LoadUnsafe(ref state, offset + 116);

			G(ref a0, ref a1, ref a2, ref a3, ref b0, ref b1, ref b2, ref b3, ref c0, ref c1, ref c2, ref c3, ref d0, ref d1, ref d2, ref d3);

			Vector256<ulong> rotatedA0 = Concat(a1, a0);
			Vector256<ulong> rotatedA1 = Concat(a0, a1);
			Vector256<ulong> rotatedC0 = Concat(c0, c1);
			Vector256<ulong> rotatedC1 = Concat(c1, c0);
			Vector256<ulong> rotatedA2 = Concat(a3, a2);
			Vector256<ulong> rotatedA3 = Concat(a2, a3);
			Vector256<ulong> rotatedC2 = Concat(c2, c3);
			Vector256<ulong> rotatedC3 = Concat(c3, c2);

			G(ref rotatedA0, ref rotatedA1, ref rotatedA2, ref rotatedA3, ref b0, ref b1, ref b2, ref b3, ref rotatedC0, ref rotatedC1, ref rotatedC2, ref rotatedC3, ref d1, ref d0, ref d3, ref d2);

			a0 = Concat(rotatedA0, rotatedA1);
			a1 = Concat(rotatedA1, rotatedA0);
			c0 = Concat(rotatedC1, rotatedC0);
			c1 = Concat(rotatedC0, rotatedC1);
			a2 = Concat(rotatedA2, rotatedA3);
			a3 = Concat(rotatedA3, rotatedA2);
			c2 = Concat(rotatedC3, rotatedC2);
			c3 = Concat(rotatedC2, rotatedC3);

			(a0 ^ Vector256.LoadUnsafe(ref final, offset)).StoreUnsafe(ref state, offset);
			(a1 ^ Vector256.LoadUnsafe(ref final, offset + 16)).StoreUnsafe(ref state, offset + 16);
			(b0 ^ Vector256.LoadUnsafe(ref final, offset + 32)).StoreUnsafe(ref state, offset + 32);
			(b1 ^ Vector256.LoadUnsafe(ref final, offset + 48)).StoreUnsafe(ref state, offset + 48);
			(c0 ^ Vector256.LoadUnsafe(ref final, offset + 64)).StoreUnsafe(ref state, offset + 64);
			(c1 ^ Vector256.LoadUnsafe(ref final, offset + 80)).StoreUnsafe(ref state, offset + 80);
			(d0 ^ Vector256.LoadUnsafe(ref final, offset + 96)).StoreUnsafe(ref state, offset + 96);
			(d1 ^ Vector256.LoadUnsafe(ref final, offset + 112)).StoreUnsafe(ref state, offset + 112);
			(a2 ^ Vector256.LoadUnsafe(ref final, offset + 4)).StoreUnsafe(ref state, offset + 4);
			(a3 ^ Vector256.LoadUnsafe(ref final, offset + 20)).StoreUnsafe(ref state, offset + 20);
			(b2 ^ Vector256.LoadUnsafe(ref final, offset + 36)).StoreUnsafe(ref state, offset + 36);
			(b3 ^ Vector256.LoadUnsafe(ref final, offset + 52)).StoreUnsafe(ref state, offset + 52);
			(c2 ^ Vector256.LoadUnsafe(ref final, offset + 68)).StoreUnsafe(ref state, offset + 68);
			(c3 ^ Vector256.LoadUnsafe(ref final, offset + 84)).StoreUnsafe(ref state, offset + 84);
			(d2 ^ Vector256.LoadUnsafe(ref final, offset + 100)).StoreUnsafe(ref state, offset + 100);
			(d3 ^ Vector256.LoadUnsafe(ref final, offset + 116)).StoreUnsafe(ref state, offset + 116);
		}
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void G(ref Vector256<ulong> a0, ref Vector256<ulong> a1, ref Vector256<ulong> b0, ref Vector256<ulong> b1, ref Vector256<ulong> c0, ref Vector256<ulong> c1, ref Vector256<ulong> d0, ref Vector256<ulong> d1)
	{
		a0 = BlaMka(a0, b0);
		a1 = BlaMka(a1, b1);
		d0 = (d0 ^ a0).RotateRightUInt64(32);
		d1 = (d1 ^ a1).RotateRightUInt64(32);
		c0 = BlaMka(c0, d0);
		c1 = BlaMka(c1, d1);
		b0 = (b0 ^ c0).RotateRightUInt64(24);
		b1 = (b1 ^ c1).RotateRightUInt64(24);
		a0 = BlaMka(a0, b0);
		a1 = BlaMka(a1, b1);
		d0 = (d0 ^ a0).RotateRightUInt64(16);
		d1 = (d1 ^ a1).RotateRightUInt64(16);
		c0 = BlaMka(c0, d0);
		c1 = BlaMka(c1, d1);
		b0 = (b0 ^ c0).RotateRightUInt64(63);
		b1 = (b1 ^ c1).RotateRightUInt64(63);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void G
	(
		ref Vector256<ulong> a0, ref Vector256<ulong> a1, ref Vector256<ulong> a2, ref Vector256<ulong> a3,
		ref Vector256<ulong> b0, ref Vector256<ulong> b1, ref Vector256<ulong> b2, ref Vector256<ulong> b3,
		ref Vector256<ulong> c0, ref Vector256<ulong> c1, ref Vector256<ulong> c2, ref Vector256<ulong> c3,
		ref Vector256<ulong> d0, ref Vector256<ulong> d1, ref Vector256<ulong> d2, ref Vector256<ulong> d3
	)
	{
		a0 = BlaMka(a0, b0);
		a1 = BlaMka(a1, b1);
		a2 = BlaMka(a2, b2);
		a3 = BlaMka(a3, b3);
		d0 = (d0 ^ a0).RotateRightUInt64(32);
		d1 = (d1 ^ a1).RotateRightUInt64(32);
		d2 = (d2 ^ a2).RotateRightUInt64(32);
		d3 = (d3 ^ a3).RotateRightUInt64(32);
		c0 = BlaMka(c0, d0);
		c1 = BlaMka(c1, d1);
		c2 = BlaMka(c2, d2);
		c3 = BlaMka(c3, d3);
		b0 = (b0 ^ c0).RotateRightUInt64(24);
		b1 = (b1 ^ c1).RotateRightUInt64(24);
		b2 = (b2 ^ c2).RotateRightUInt64(24);
		b3 = (b3 ^ c3).RotateRightUInt64(24);
		a0 = BlaMka(a0, b0);
		a1 = BlaMka(a1, b1);
		a2 = BlaMka(a2, b2);
		a3 = BlaMka(a3, b3);
		d0 = (d0 ^ a0).RotateRightUInt64(16);
		d1 = (d1 ^ a1).RotateRightUInt64(16);
		d2 = (d2 ^ a2).RotateRightUInt64(16);
		d3 = (d3 ^ a3).RotateRightUInt64(16);
		c0 = BlaMka(c0, d0);
		c1 = BlaMka(c1, d1);
		c2 = BlaMka(c2, d2);
		c3 = BlaMka(c3, d3);
		b0 = (b0 ^ c0).RotateRightUInt64(63);
		b1 = (b1 ^ c1).RotateRightUInt64(63);
		b2 = (b2 ^ c2).RotateRightUInt64(63);
		b3 = (b3 ^ c3).RotateRightUInt64(63);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector256<ulong> BlaMka(Vector256<ulong> x, Vector256<ulong> y)
	{
		Vector256<ulong> product = Avx2.Multiply(x.AsUInt32(), y.AsUInt32());
		return x + y + (product + product);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector256<ulong> Concat(Vector256<ulong> left, Vector256<ulong> right)
	{
		return Avx2.AlignRight(right.AsByte(), left.AsByte(), 8).AsUInt64();
	}
}
