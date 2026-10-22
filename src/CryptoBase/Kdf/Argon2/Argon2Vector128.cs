namespace CryptoBase.Kdf.Argon2;

internal readonly struct Argon2Vector128 : IArgon2Kernel
{
	public static bool IsSupported => Sse2.IsSupported;

	[MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.AggressiveOptimization)]
	public static void Compress(ref Argon2Block previous, ref Argon2Block reference, ref Argon2Block destination, ref Argon2Block scratch, bool xorDestination)
	{
		Debug.Assert(IsSupported);

		ref ulong x = ref previous[0];
		ref ulong y = ref reference[0];
		ref ulong state = ref destination[0];
		ref ulong final = ref scratch[0];

		for (nuint offset = 0; offset < Argon2Block.QWordCount; offset += 16)
		{
			Vector128<ulong> a0 = Vector128.LoadUnsafe(ref x, offset) ^ Vector128.LoadUnsafe(ref y, offset);
			Vector128<ulong> a1 = Vector128.LoadUnsafe(ref x, offset + 2) ^ Vector128.LoadUnsafe(ref y, offset + 2);
			Vector128<ulong> b0 = Vector128.LoadUnsafe(ref x, offset + 4) ^ Vector128.LoadUnsafe(ref y, offset + 4);
			Vector128<ulong> b1 = Vector128.LoadUnsafe(ref x, offset + 6) ^ Vector128.LoadUnsafe(ref y, offset + 6);
			Vector128<ulong> c0 = Vector128.LoadUnsafe(ref x, offset + 8) ^ Vector128.LoadUnsafe(ref y, offset + 8);
			Vector128<ulong> c1 = Vector128.LoadUnsafe(ref x, offset + 10) ^ Vector128.LoadUnsafe(ref y, offset + 10);
			Vector128<ulong> d0 = Vector128.LoadUnsafe(ref x, offset + 12) ^ Vector128.LoadUnsafe(ref y, offset + 12);
			Vector128<ulong> d1 = Vector128.LoadUnsafe(ref x, offset + 14) ^ Vector128.LoadUnsafe(ref y, offset + 14);

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
			}

			Round(ref a0, ref a1, ref b0, ref b1, ref c0, ref c1, ref d0, ref d1);

			a0.StoreUnsafe(ref state, offset);
			a1.StoreUnsafe(ref state, offset + 2);
			b0.StoreUnsafe(ref state, offset + 4);
			b1.StoreUnsafe(ref state, offset + 6);
			c0.StoreUnsafe(ref state, offset + 8);
			c1.StoreUnsafe(ref state, offset + 10);
			d0.StoreUnsafe(ref state, offset + 12);
			d1.StoreUnsafe(ref state, offset + 14);
		}

		for (nuint offset = 0; offset < 16; offset += 2)
		{
			Vector128<ulong> a0 = Vector128.LoadUnsafe(ref state, offset);
			Vector128<ulong> a1 = Vector128.LoadUnsafe(ref state, offset + 16);
			Vector128<ulong> b0 = Vector128.LoadUnsafe(ref state, offset + 32);
			Vector128<ulong> b1 = Vector128.LoadUnsafe(ref state, offset + 48);
			Vector128<ulong> c0 = Vector128.LoadUnsafe(ref state, offset + 64);
			Vector128<ulong> c1 = Vector128.LoadUnsafe(ref state, offset + 80);
			Vector128<ulong> d0 = Vector128.LoadUnsafe(ref state, offset + 96);
			Vector128<ulong> d1 = Vector128.LoadUnsafe(ref state, offset + 112);

			Round(ref a0, ref a1, ref b0, ref b1, ref c0, ref c1, ref d0, ref d1);

			(a0 ^ Vector128.LoadUnsafe(ref final, offset)).StoreUnsafe(ref state, offset);
			(a1 ^ Vector128.LoadUnsafe(ref final, offset + 16)).StoreUnsafe(ref state, offset + 16);
			(b0 ^ Vector128.LoadUnsafe(ref final, offset + 32)).StoreUnsafe(ref state, offset + 32);
			(b1 ^ Vector128.LoadUnsafe(ref final, offset + 48)).StoreUnsafe(ref state, offset + 48);
			(c0 ^ Vector128.LoadUnsafe(ref final, offset + 64)).StoreUnsafe(ref state, offset + 64);
			(c1 ^ Vector128.LoadUnsafe(ref final, offset + 80)).StoreUnsafe(ref state, offset + 80);
			(d0 ^ Vector128.LoadUnsafe(ref final, offset + 96)).StoreUnsafe(ref state, offset + 96);
			(d1 ^ Vector128.LoadUnsafe(ref final, offset + 112)).StoreUnsafe(ref state, offset + 112);
		}
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void Round(ref Vector128<ulong> a0, ref Vector128<ulong> a1, ref Vector128<ulong> b0, ref Vector128<ulong> b1, ref Vector128<ulong> c0, ref Vector128<ulong> c1, ref Vector128<ulong> d0, ref Vector128<ulong> d1)
	{
		G(ref a0, ref a1, ref b0, ref b1, ref c0, ref c1, ref d0, ref d1);

		// Diagonalizing a, c and d leaves b, which G finishes last, off the shuffle path.
		Vector128<ulong> rotatedA0 = Concat(a1, a0);
		Vector128<ulong> rotatedA1 = Concat(a0, a1);
		Vector128<ulong> rotatedC0 = Concat(c0, c1);
		Vector128<ulong> rotatedC1 = Concat(c1, c0);

		G(ref rotatedA0, ref rotatedA1, ref b0, ref b1, ref rotatedC0, ref rotatedC1, ref d1, ref d0);

		a0 = Concat(rotatedA0, rotatedA1);
		a1 = Concat(rotatedA1, rotatedA0);
		c0 = Concat(rotatedC1, rotatedC0);
		c1 = Concat(rotatedC0, rotatedC1);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void G(ref Vector128<ulong> a0, ref Vector128<ulong> a1, ref Vector128<ulong> b0, ref Vector128<ulong> b1, ref Vector128<ulong> c0, ref Vector128<ulong> c1, ref Vector128<ulong> d0, ref Vector128<ulong> d1)
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
	private static Vector128<ulong> BlaMka(Vector128<ulong> x, Vector128<ulong> y)
	{
		Vector128<ulong> product = Sse2.Multiply(x.AsUInt32(), y.AsUInt32());
		return x + y + (product + product);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector128<ulong> Concat(Vector128<ulong> left, Vector128<ulong> right)
	{
		if (Ssse3.IsSupported)
		{
			return Ssse3.AlignRight(right.AsByte(), left.AsByte(), 8).AsUInt64();
		}

		return Sse2.Shuffle(left.AsDouble(), right.AsDouble(), 0b01).AsUInt64();
	}
}
