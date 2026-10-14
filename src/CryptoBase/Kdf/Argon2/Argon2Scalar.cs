namespace CryptoBase.Kdf.Argon2;

internal readonly struct Argon2Scalar : IArgon2Kernel
{
	public static bool IsSupported => true;

	[MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.AggressiveOptimization)]
	public static void Compress(ref Argon2Block previous, ref Argon2Block reference, ref Argon2Block destination, ref Argon2Block scratch, bool xorDestination)
	{
		ref ulong x = ref previous[0];
		ref ulong y = ref reference[0];
		ref ulong state = ref destination[0];
		ref ulong final = ref scratch[0];
		ulong destinationMask = xorDestination ? ulong.MaxValue : 0;

		for (nuint offset = 0; offset < Argon2Block.QWordCount; offset += 16)
		{
			ulong v0 = LoadR(ref x, ref y, ref state, ref final, offset, destinationMask);
			ulong v1 = LoadR(ref x, ref y, ref state, ref final, offset + 1, destinationMask);
			ulong v2 = LoadR(ref x, ref y, ref state, ref final, offset + 2, destinationMask);
			ulong v3 = LoadR(ref x, ref y, ref state, ref final, offset + 3, destinationMask);
			ulong v4 = LoadR(ref x, ref y, ref state, ref final, offset + 4, destinationMask);
			ulong v5 = LoadR(ref x, ref y, ref state, ref final, offset + 5, destinationMask);
			ulong v6 = LoadR(ref x, ref y, ref state, ref final, offset + 6, destinationMask);
			ulong v7 = LoadR(ref x, ref y, ref state, ref final, offset + 7, destinationMask);
			ulong v8 = LoadR(ref x, ref y, ref state, ref final, offset + 8, destinationMask);
			ulong v9 = LoadR(ref x, ref y, ref state, ref final, offset + 9, destinationMask);
			ulong v10 = LoadR(ref x, ref y, ref state, ref final, offset + 10, destinationMask);
			ulong v11 = LoadR(ref x, ref y, ref state, ref final, offset + 11, destinationMask);
			ulong v12 = LoadR(ref x, ref y, ref state, ref final, offset + 12, destinationMask);
			ulong v13 = LoadR(ref x, ref y, ref state, ref final, offset + 13, destinationMask);
			ulong v14 = LoadR(ref x, ref y, ref state, ref final, offset + 14, destinationMask);
			ulong v15 = LoadR(ref x, ref y, ref state, ref final, offset + 15, destinationMask);

			Round(ref v0, ref v1, ref v2, ref v3, ref v4, ref v5, ref v6, ref v7, ref v8, ref v9, ref v10, ref v11, ref v12, ref v13, ref v14, ref v15);

			Unsafe.Add(ref state, offset) = v0;
			Unsafe.Add(ref state, offset + 1) = v1;
			Unsafe.Add(ref state, offset + 2) = v2;
			Unsafe.Add(ref state, offset + 3) = v3;
			Unsafe.Add(ref state, offset + 4) = v4;
			Unsafe.Add(ref state, offset + 5) = v5;
			Unsafe.Add(ref state, offset + 6) = v6;
			Unsafe.Add(ref state, offset + 7) = v7;
			Unsafe.Add(ref state, offset + 8) = v8;
			Unsafe.Add(ref state, offset + 9) = v9;
			Unsafe.Add(ref state, offset + 10) = v10;
			Unsafe.Add(ref state, offset + 11) = v11;
			Unsafe.Add(ref state, offset + 12) = v12;
			Unsafe.Add(ref state, offset + 13) = v13;
			Unsafe.Add(ref state, offset + 14) = v14;
			Unsafe.Add(ref state, offset + 15) = v15;
		}

		for (nuint offset = 0; offset < 16; offset += 2)
		{
			ulong v0 = Unsafe.Add(ref state, offset);
			ulong v1 = Unsafe.Add(ref state, offset + 1);
			ulong v2 = Unsafe.Add(ref state, offset + 16);
			ulong v3 = Unsafe.Add(ref state, offset + 17);
			ulong v4 = Unsafe.Add(ref state, offset + 32);
			ulong v5 = Unsafe.Add(ref state, offset + 33);
			ulong v6 = Unsafe.Add(ref state, offset + 48);
			ulong v7 = Unsafe.Add(ref state, offset + 49);
			ulong v8 = Unsafe.Add(ref state, offset + 64);
			ulong v9 = Unsafe.Add(ref state, offset + 65);
			ulong v10 = Unsafe.Add(ref state, offset + 80);
			ulong v11 = Unsafe.Add(ref state, offset + 81);
			ulong v12 = Unsafe.Add(ref state, offset + 96);
			ulong v13 = Unsafe.Add(ref state, offset + 97);
			ulong v14 = Unsafe.Add(ref state, offset + 112);
			ulong v15 = Unsafe.Add(ref state, offset + 113);

			Round(ref v0, ref v1, ref v2, ref v3, ref v4, ref v5, ref v6, ref v7, ref v8, ref v9, ref v10, ref v11, ref v12, ref v13, ref v14, ref v15);

			Unsafe.Add(ref state, offset) = v0 ^ Unsafe.Add(ref final, offset);
			Unsafe.Add(ref state, offset + 1) = v1 ^ Unsafe.Add(ref final, offset + 1);
			Unsafe.Add(ref state, offset + 16) = v2 ^ Unsafe.Add(ref final, offset + 16);
			Unsafe.Add(ref state, offset + 17) = v3 ^ Unsafe.Add(ref final, offset + 17);
			Unsafe.Add(ref state, offset + 32) = v4 ^ Unsafe.Add(ref final, offset + 32);
			Unsafe.Add(ref state, offset + 33) = v5 ^ Unsafe.Add(ref final, offset + 33);
			Unsafe.Add(ref state, offset + 48) = v6 ^ Unsafe.Add(ref final, offset + 48);
			Unsafe.Add(ref state, offset + 49) = v7 ^ Unsafe.Add(ref final, offset + 49);
			Unsafe.Add(ref state, offset + 64) = v8 ^ Unsafe.Add(ref final, offset + 64);
			Unsafe.Add(ref state, offset + 65) = v9 ^ Unsafe.Add(ref final, offset + 65);
			Unsafe.Add(ref state, offset + 80) = v10 ^ Unsafe.Add(ref final, offset + 80);
			Unsafe.Add(ref state, offset + 81) = v11 ^ Unsafe.Add(ref final, offset + 81);
			Unsafe.Add(ref state, offset + 96) = v12 ^ Unsafe.Add(ref final, offset + 96);
			Unsafe.Add(ref state, offset + 97) = v13 ^ Unsafe.Add(ref final, offset + 97);
			Unsafe.Add(ref state, offset + 112) = v14 ^ Unsafe.Add(ref final, offset + 112);
			Unsafe.Add(ref state, offset + 113) = v15 ^ Unsafe.Add(ref final, offset + 113);
		}
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static ulong LoadR(ref ulong x, ref ulong y, ref ulong state, ref ulong final, nuint i, ulong destinationMask)
	{
		ulong r = Unsafe.Add(ref x, i) ^ Unsafe.Add(ref y, i);
		Unsafe.Add(ref final, i) = r ^ Unsafe.Add(ref state, i) & destinationMask;
		return r;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void Round
	(
		ref ulong v0, ref ulong v1, ref ulong v2, ref ulong v3,
		ref ulong v4, ref ulong v5, ref ulong v6, ref ulong v7,
		ref ulong v8, ref ulong v9, ref ulong v10, ref ulong v11,
		ref ulong v12, ref ulong v13, ref ulong v14, ref ulong v15
	)
	{
		Step(ref v0, ref v1, ref v2, ref v3, ref v4, ref v5, ref v6, ref v7, ref v8, ref v9, ref v10, ref v11, ref v12, ref v13, ref v14, ref v15);
		Step(ref v0, ref v1, ref v2, ref v3, ref v5, ref v6, ref v7, ref v4, ref v10, ref v11, ref v8, ref v9, ref v15, ref v12, ref v13, ref v14);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void Step
	(
		ref ulong a0, ref ulong a1, ref ulong a2, ref ulong a3,
		ref ulong b0, ref ulong b1, ref ulong b2, ref ulong b3,
		ref ulong c0, ref ulong c1, ref ulong c2, ref ulong c3,
		ref ulong d0, ref ulong d1, ref ulong d2, ref ulong d3
	)
	{
		a0 = BlaMka(a0, b0);
		a1 = BlaMka(a1, b1);
		a2 = BlaMka(a2, b2);
		a3 = BlaMka(a3, b3);
		d0 = BitOperations.RotateRight(d0 ^ a0, 32);
		d1 = BitOperations.RotateRight(d1 ^ a1, 32);
		d2 = BitOperations.RotateRight(d2 ^ a2, 32);
		d3 = BitOperations.RotateRight(d3 ^ a3, 32);
		c0 = BlaMka(c0, d0);
		c1 = BlaMka(c1, d1);
		c2 = BlaMka(c2, d2);
		c3 = BlaMka(c3, d3);
		b0 = BitOperations.RotateRight(b0 ^ c0, 24);
		b1 = BitOperations.RotateRight(b1 ^ c1, 24);
		b2 = BitOperations.RotateRight(b2 ^ c2, 24);
		b3 = BitOperations.RotateRight(b3 ^ c3, 24);
		a0 = BlaMka(a0, b0);
		a1 = BlaMka(a1, b1);
		a2 = BlaMka(a2, b2);
		a3 = BlaMka(a3, b3);
		d0 = BitOperations.RotateRight(d0 ^ a0, 16);
		d1 = BitOperations.RotateRight(d1 ^ a1, 16);
		d2 = BitOperations.RotateRight(d2 ^ a2, 16);
		d3 = BitOperations.RotateRight(d3 ^ a3, 16);
		c0 = BlaMka(c0, d0);
		c1 = BlaMka(c1, d1);
		c2 = BlaMka(c2, d2);
		c3 = BlaMka(c3, d3);
		b0 = BitOperations.RotateRight(b0 ^ c0, 63);
		b1 = BitOperations.RotateRight(b1 ^ c1, 63);
		b2 = BitOperations.RotateRight(b2 ^ c2, 63);
		b3 = BitOperations.RotateRight(b3 ^ c3, 63);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static ulong BlaMka(ulong x, ulong y)
	{
		ulong product = (ulong)(uint)x * (uint)y;
		return x + y + (product << 1);
	}
}
