namespace CryptoBase.Kdf.Argon2;

// Two rows or two columns per iteration: the 32 NEON registers hold both, and their four independent chains hide the multiply latency.
internal readonly struct Argon2AdvSimd : IArgon2Kernel
{
	public static bool IsSupported => AdvSimd.Arm64.IsSupported;

	[MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.AggressiveOptimization)]
	public static void Compress(ref Argon2Block previous, ref Argon2Block reference, ref Argon2Block destination, ref Argon2Block scratch, bool xorDestination)
	{
		Debug.Assert(IsSupported);

		ref ulong x = ref previous[0];
		ref ulong y = ref reference[0];
		ref ulong state = ref destination[0];
		ref ulong final = ref scratch[0];

		for (nuint offset = 0; offset < Argon2Block.QWordCount; offset += 32)
		{
			Vector128<ulong> a0 = Vector128.LoadUnsafe(ref x, offset) ^ Vector128.LoadUnsafe(ref y, offset);
			Vector128<ulong> a1 = Vector128.LoadUnsafe(ref x, offset + 2) ^ Vector128.LoadUnsafe(ref y, offset + 2);
			Vector128<ulong> b0 = Vector128.LoadUnsafe(ref x, offset + 4) ^ Vector128.LoadUnsafe(ref y, offset + 4);
			Vector128<ulong> b1 = Vector128.LoadUnsafe(ref x, offset + 6) ^ Vector128.LoadUnsafe(ref y, offset + 6);
			Vector128<ulong> c0 = Vector128.LoadUnsafe(ref x, offset + 8) ^ Vector128.LoadUnsafe(ref y, offset + 8);
			Vector128<ulong> c1 = Vector128.LoadUnsafe(ref x, offset + 10) ^ Vector128.LoadUnsafe(ref y, offset + 10);
			Vector128<ulong> d0 = Vector128.LoadUnsafe(ref x, offset + 12) ^ Vector128.LoadUnsafe(ref y, offset + 12);
			Vector128<ulong> d1 = Vector128.LoadUnsafe(ref x, offset + 14) ^ Vector128.LoadUnsafe(ref y, offset + 14);
			Vector128<ulong> a2 = Vector128.LoadUnsafe(ref x, offset + 16) ^ Vector128.LoadUnsafe(ref y, offset + 16);
			Vector128<ulong> a3 = Vector128.LoadUnsafe(ref x, offset + 18) ^ Vector128.LoadUnsafe(ref y, offset + 18);
			Vector128<ulong> b2 = Vector128.LoadUnsafe(ref x, offset + 20) ^ Vector128.LoadUnsafe(ref y, offset + 20);
			Vector128<ulong> b3 = Vector128.LoadUnsafe(ref x, offset + 22) ^ Vector128.LoadUnsafe(ref y, offset + 22);
			Vector128<ulong> c2 = Vector128.LoadUnsafe(ref x, offset + 24) ^ Vector128.LoadUnsafe(ref y, offset + 24);
			Vector128<ulong> c3 = Vector128.LoadUnsafe(ref x, offset + 26) ^ Vector128.LoadUnsafe(ref y, offset + 26);
			Vector128<ulong> d2 = Vector128.LoadUnsafe(ref x, offset + 28) ^ Vector128.LoadUnsafe(ref y, offset + 28);
			Vector128<ulong> d3 = Vector128.LoadUnsafe(ref x, offset + 30) ^ Vector128.LoadUnsafe(ref y, offset + 30);

			if (xorDestination)
			{
				(a0 ^ Vector128.LoadUnsafe(ref state, offset)).StoreUnsafe(ref final, offset);
				(a1 ^ Vector128.LoadUnsafe(ref state, offset + 2)).StoreUnsafe(ref final, offset + 2);
				(b0 ^ Vector128.LoadUnsafe(ref state, offset + 4)).StoreUnsafe(ref final, offset + 4);
				(b1 ^ Vector128.LoadUnsafe(ref state, offset + 6)).StoreUnsafe(ref final, offset + 6);
				(c0 ^ Vector128.LoadUnsafe(ref state, offset + 8)).StoreUnsafe(ref final, offset + 8);
				(c1 ^ Vector128.LoadUnsafe(ref state, offset + 10)).StoreUnsafe(ref final, offset + 10);
				(d0 ^ Vector128.LoadUnsafe(ref state, offset + 12)).StoreUnsafe(ref final, offset + 12);
				(d1 ^ Vector128.LoadUnsafe(ref state, offset + 14)).StoreUnsafe(ref final, offset + 14);
				(a2 ^ Vector128.LoadUnsafe(ref state, offset + 16)).StoreUnsafe(ref final, offset + 16);
				(a3 ^ Vector128.LoadUnsafe(ref state, offset + 18)).StoreUnsafe(ref final, offset + 18);
				(b2 ^ Vector128.LoadUnsafe(ref state, offset + 20)).StoreUnsafe(ref final, offset + 20);
				(b3 ^ Vector128.LoadUnsafe(ref state, offset + 22)).StoreUnsafe(ref final, offset + 22);
				(c2 ^ Vector128.LoadUnsafe(ref state, offset + 24)).StoreUnsafe(ref final, offset + 24);
				(c3 ^ Vector128.LoadUnsafe(ref state, offset + 26)).StoreUnsafe(ref final, offset + 26);
				(d2 ^ Vector128.LoadUnsafe(ref state, offset + 28)).StoreUnsafe(ref final, offset + 28);
				(d3 ^ Vector128.LoadUnsafe(ref state, offset + 30)).StoreUnsafe(ref final, offset + 30);
			}
			else
			{
				a0.StoreUnsafe(ref final, offset);
				a1.StoreUnsafe(ref final, offset + 2);
				b0.StoreUnsafe(ref final, offset + 4);
				b1.StoreUnsafe(ref final, offset + 6);
				c0.StoreUnsafe(ref final, offset + 8);
				c1.StoreUnsafe(ref final, offset + 10);
				d0.StoreUnsafe(ref final, offset + 12);
				d1.StoreUnsafe(ref final, offset + 14);
				a2.StoreUnsafe(ref final, offset + 16);
				a3.StoreUnsafe(ref final, offset + 18);
				b2.StoreUnsafe(ref final, offset + 20);
				b3.StoreUnsafe(ref final, offset + 22);
				c2.StoreUnsafe(ref final, offset + 24);
				c3.StoreUnsafe(ref final, offset + 26);
				d2.StoreUnsafe(ref final, offset + 28);
				d3.StoreUnsafe(ref final, offset + 30);
			}

			Round(ref a0, ref a1, ref b0, ref b1, ref c0, ref c1, ref d0, ref d1, ref a2, ref a3, ref b2, ref b3, ref c2, ref c3, ref d2, ref d3);

			a0.StoreUnsafe(ref state, offset);
			a1.StoreUnsafe(ref state, offset + 2);
			b0.StoreUnsafe(ref state, offset + 4);
			b1.StoreUnsafe(ref state, offset + 6);
			c0.StoreUnsafe(ref state, offset + 8);
			c1.StoreUnsafe(ref state, offset + 10);
			d0.StoreUnsafe(ref state, offset + 12);
			d1.StoreUnsafe(ref state, offset + 14);
			a2.StoreUnsafe(ref state, offset + 16);
			a3.StoreUnsafe(ref state, offset + 18);
			b2.StoreUnsafe(ref state, offset + 20);
			b3.StoreUnsafe(ref state, offset + 22);
			c2.StoreUnsafe(ref state, offset + 24);
			c3.StoreUnsafe(ref state, offset + 26);
			d2.StoreUnsafe(ref state, offset + 28);
			d3.StoreUnsafe(ref state, offset + 30);
		}

		for (nuint offset = 0; offset < 16; offset += 4)
		{
			Vector128<ulong> a0 = Vector128.LoadUnsafe(ref state, offset);
			Vector128<ulong> a1 = Vector128.LoadUnsafe(ref state, offset + 16);
			Vector128<ulong> b0 = Vector128.LoadUnsafe(ref state, offset + 32);
			Vector128<ulong> b1 = Vector128.LoadUnsafe(ref state, offset + 48);
			Vector128<ulong> c0 = Vector128.LoadUnsafe(ref state, offset + 64);
			Vector128<ulong> c1 = Vector128.LoadUnsafe(ref state, offset + 80);
			Vector128<ulong> d0 = Vector128.LoadUnsafe(ref state, offset + 96);
			Vector128<ulong> d1 = Vector128.LoadUnsafe(ref state, offset + 112);
			Vector128<ulong> a2 = Vector128.LoadUnsafe(ref state, offset + 2);
			Vector128<ulong> a3 = Vector128.LoadUnsafe(ref state, offset + 18);
			Vector128<ulong> b2 = Vector128.LoadUnsafe(ref state, offset + 34);
			Vector128<ulong> b3 = Vector128.LoadUnsafe(ref state, offset + 50);
			Vector128<ulong> c2 = Vector128.LoadUnsafe(ref state, offset + 66);
			Vector128<ulong> c3 = Vector128.LoadUnsafe(ref state, offset + 82);
			Vector128<ulong> d2 = Vector128.LoadUnsafe(ref state, offset + 98);
			Vector128<ulong> d3 = Vector128.LoadUnsafe(ref state, offset + 114);

			Round(ref a0, ref a1, ref b0, ref b1, ref c0, ref c1, ref d0, ref d1, ref a2, ref a3, ref b2, ref b3, ref c2, ref c3, ref d2, ref d3);

			(a0 ^ Vector128.LoadUnsafe(ref final, offset)).StoreUnsafe(ref state, offset);
			(a1 ^ Vector128.LoadUnsafe(ref final, offset + 16)).StoreUnsafe(ref state, offset + 16);
			(b0 ^ Vector128.LoadUnsafe(ref final, offset + 32)).StoreUnsafe(ref state, offset + 32);
			(b1 ^ Vector128.LoadUnsafe(ref final, offset + 48)).StoreUnsafe(ref state, offset + 48);
			(c0 ^ Vector128.LoadUnsafe(ref final, offset + 64)).StoreUnsafe(ref state, offset + 64);
			(c1 ^ Vector128.LoadUnsafe(ref final, offset + 80)).StoreUnsafe(ref state, offset + 80);
			(d0 ^ Vector128.LoadUnsafe(ref final, offset + 96)).StoreUnsafe(ref state, offset + 96);
			(d1 ^ Vector128.LoadUnsafe(ref final, offset + 112)).StoreUnsafe(ref state, offset + 112);
			(a2 ^ Vector128.LoadUnsafe(ref final, offset + 2)).StoreUnsafe(ref state, offset + 2);
			(a3 ^ Vector128.LoadUnsafe(ref final, offset + 18)).StoreUnsafe(ref state, offset + 18);
			(b2 ^ Vector128.LoadUnsafe(ref final, offset + 34)).StoreUnsafe(ref state, offset + 34);
			(b3 ^ Vector128.LoadUnsafe(ref final, offset + 50)).StoreUnsafe(ref state, offset + 50);
			(c2 ^ Vector128.LoadUnsafe(ref final, offset + 66)).StoreUnsafe(ref state, offset + 66);
			(c3 ^ Vector128.LoadUnsafe(ref final, offset + 82)).StoreUnsafe(ref state, offset + 82);
			(d2 ^ Vector128.LoadUnsafe(ref final, offset + 98)).StoreUnsafe(ref state, offset + 98);
			(d3 ^ Vector128.LoadUnsafe(ref final, offset + 114)).StoreUnsafe(ref state, offset + 114);
		}
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void Round
	(
		ref Vector128<ulong> a0, ref Vector128<ulong> a1, ref Vector128<ulong> b0, ref Vector128<ulong> b1,
		ref Vector128<ulong> c0, ref Vector128<ulong> c1, ref Vector128<ulong> d0, ref Vector128<ulong> d1,
		ref Vector128<ulong> a2, ref Vector128<ulong> a3, ref Vector128<ulong> b2, ref Vector128<ulong> b3,
		ref Vector128<ulong> c2, ref Vector128<ulong> c3, ref Vector128<ulong> d2, ref Vector128<ulong> d3
	)
	{
		G(ref a0, ref a1, ref b0, ref b1, ref c0, ref c1, ref d0, ref d1, ref a2, ref a3, ref b2, ref b3, ref c2, ref c3, ref d2, ref d3);

		// Diagonalizing a, c and d leaves b, which G finishes last, off the shuffle path.
		Vector128<ulong> rotatedA0 = AdvSimd.ExtractVector128(a1, a0, 1);
		Vector128<ulong> rotatedA1 = AdvSimd.ExtractVector128(a0, a1, 1);
		Vector128<ulong> rotatedC0 = AdvSimd.ExtractVector128(c0, c1, 1);
		Vector128<ulong> rotatedC1 = AdvSimd.ExtractVector128(c1, c0, 1);
		Vector128<ulong> rotatedA2 = AdvSimd.ExtractVector128(a3, a2, 1);
		Vector128<ulong> rotatedA3 = AdvSimd.ExtractVector128(a2, a3, 1);
		Vector128<ulong> rotatedC2 = AdvSimd.ExtractVector128(c2, c3, 1);
		Vector128<ulong> rotatedC3 = AdvSimd.ExtractVector128(c3, c2, 1);

		G(ref rotatedA0, ref rotatedA1, ref b0, ref b1, ref rotatedC0, ref rotatedC1, ref d1, ref d0, ref rotatedA2, ref rotatedA3, ref b2, ref b3, ref rotatedC2, ref rotatedC3, ref d3, ref d2);

		a0 = AdvSimd.ExtractVector128(rotatedA0, rotatedA1, 1);
		a1 = AdvSimd.ExtractVector128(rotatedA1, rotatedA0, 1);
		c0 = AdvSimd.ExtractVector128(rotatedC1, rotatedC0, 1);
		c1 = AdvSimd.ExtractVector128(rotatedC0, rotatedC1, 1);
		a2 = AdvSimd.ExtractVector128(rotatedA2, rotatedA3, 1);
		a3 = AdvSimd.ExtractVector128(rotatedA3, rotatedA2, 1);
		c2 = AdvSimd.ExtractVector128(rotatedC3, rotatedC2, 1);
		c3 = AdvSimd.ExtractVector128(rotatedC2, rotatedC3, 1);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void G
	(
		ref Vector128<ulong> a0, ref Vector128<ulong> a1, ref Vector128<ulong> b0, ref Vector128<ulong> b1,
		ref Vector128<ulong> c0, ref Vector128<ulong> c1, ref Vector128<ulong> d0, ref Vector128<ulong> d1,
		ref Vector128<ulong> a2, ref Vector128<ulong> a3, ref Vector128<ulong> b2, ref Vector128<ulong> b3,
		ref Vector128<ulong> c2, ref Vector128<ulong> c3, ref Vector128<ulong> d2, ref Vector128<ulong> d3
	)
	{
		BlaMka(ref a0, ref a1, b0, b1);
		BlaMka(ref a2, ref a3, b2, b3);
		d0 = AdvSimd.ReverseElement32(d0 ^ a0);
		d1 = AdvSimd.ReverseElement32(d1 ^ a1);
		d2 = AdvSimd.ReverseElement32(d2 ^ a2);
		d3 = AdvSimd.ReverseElement32(d3 ^ a3);
		BlaMka(ref c0, ref c1, d0, d1);
		BlaMka(ref c2, ref c3, d2, d3);
		b0 = RotateRight24(b0 ^ c0);
		b1 = RotateRight24(b1 ^ c1);
		b2 = RotateRight24(b2 ^ c2);
		b3 = RotateRight24(b3 ^ c3);
		BlaMka(ref a0, ref a1, b0, b1);
		BlaMka(ref a2, ref a3, b2, b3);
		d0 = RotateRight16(d0 ^ a0);
		d1 = RotateRight16(d1 ^ a1);
		d2 = RotateRight16(d2 ^ a2);
		d3 = RotateRight16(d3 ^ a3);
		BlaMka(ref c0, ref c1, d0, d1);
		BlaMka(ref c2, ref c3, d2, d3);
		b0 = RotateRight63(b0 ^ c0);
		b1 = RotateRight63(b1 ^ c1);
		b2 = RotateRight63(b2 ^ c2);
		b3 = RotateRight63(b3 ^ c3);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void BlaMka(ref Vector128<ulong> x0, ref Vector128<ulong> x1, Vector128<ulong> y0, Vector128<ulong> y1)
	{
		// One UZP1 gathers the low halves of both vectors, and accumulating the product twice with UMLAL replaces a doubling and an addition.
		Vector128<uint> xLow = AdvSimd.Arm64.UnzipEven(x0.AsUInt32(), x1.AsUInt32());
		Vector128<uint> yLow = AdvSimd.Arm64.UnzipEven(y0.AsUInt32(), y1.AsUInt32());
		Vector128<ulong> sum0 = AdvSimd.MultiplyWideningLowerAndAdd(x0 + y0, xLow.GetLower(), yLow.GetLower());
		Vector128<ulong> sum1 = AdvSimd.MultiplyWideningUpperAndAdd(x1 + y1, xLow, yLow);
		x0 = AdvSimd.MultiplyWideningLowerAndAdd(sum0, xLow.GetLower(), yLow.GetLower());
		x1 = AdvSimd.MultiplyWideningUpperAndAdd(sum1, xLow, yLow);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector128<ulong> RotateRight24(Vector128<ulong> value)
	{
		return Vector128.Shuffle(value.AsByte(), Vector128.Create((byte)3, 4, 5, 6, 7, 0, 1, 2, 11, 12, 13, 14, 15, 8, 9, 10)).AsUInt64();
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector128<ulong> RotateRight16(Vector128<ulong> value)
	{
		return Vector128.Shuffle(value.AsByte(), Vector128.Create((byte)2, 3, 4, 5, 6, 7, 0, 1, 10, 11, 12, 13, 14, 15, 8, 9)).AsUInt64();
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector128<ulong> RotateRight63(Vector128<ulong> value)
	{
		return AdvSimd.ShiftRightAndInsert(value + value, value, 63);
	}
}
