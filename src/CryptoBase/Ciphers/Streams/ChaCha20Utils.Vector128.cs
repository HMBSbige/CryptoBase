namespace CryptoBase.Ciphers.Streams;

internal static partial class ChaCha20Utils
{
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void QuarterRound(ref Vector128<uint> a, ref Vector128<uint> b, ref Vector128<uint> c, ref Vector128<uint> d)
	{
		a += b;
		d = (a ^ d).RotateLeftUInt32(16);

		c += d;
		b = (b ^ c).RotateLeftUInt32(12);

		a += b;
		d = (a ^ d).RotateLeftUInt32(8);

		c += d;
		b = (b ^ c).RotateLeftUInt32(7);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void QuarterRoundLocal(ref Vector128<uint> a, ref Vector128<uint> b, ref Vector128<uint> c, ref Vector128<uint> d)
	{
		Vector128<uint> x = a;
		Vector128<uint> y = b;
		Vector128<uint> z = c;
		Vector128<uint> w = d;
		QuarterRound(ref x, ref y, ref z, ref w);
		a = x;
		b = y;
		c = z;
		d = w;
	}

	private static int XorVector128(ref uint stateRef, ref byte input, ref byte output, int length)
	{
		ref ulong counter = ref GetCounterOriginal(ref stateRef);
		int processed = 0;
		Vector128<uint> s00 = Vector128.Create(Unsafe.Add(ref stateRef, 0));
		Vector128<uint> s01 = Vector128.Create(Unsafe.Add(ref stateRef, 1));
		Vector128<uint> s02 = Vector128.Create(Unsafe.Add(ref stateRef, 2));
		Vector128<uint> s03 = Vector128.Create(Unsafe.Add(ref stateRef, 3));
		Vector128<uint> s04 = Vector128.Create(Unsafe.Add(ref stateRef, 4));
		Vector128<uint> s05 = Vector128.Create(Unsafe.Add(ref stateRef, 5));
		Vector128<uint> s06 = Vector128.Create(Unsafe.Add(ref stateRef, 6));
		Vector128<uint> s07 = Vector128.Create(Unsafe.Add(ref stateRef, 7));
		Vector128<uint> s08 = Vector128.Create(Unsafe.Add(ref stateRef, 8));
		Vector128<uint> s09 = Vector128.Create(Unsafe.Add(ref stateRef, 9));
		Vector128<uint> s10 = Vector128.Create(Unsafe.Add(ref stateRef, 10));
		Vector128<uint> s11 = Vector128.Create(Unsafe.Add(ref stateRef, 11));
		Vector128<uint> s13 = Vector128.Create(Unsafe.Add(ref stateRef, 13));
		Vector128<uint> s14 = Vector128.Create(Unsafe.Add(ref stateRef, 14));
		Vector128<uint> s15 = Vector128.Create(Unsafe.Add(ref stateRef, 15));

		int minimumBatchLength = AdvSimd.Arm64.IsSupported ? 192 : 256;

		while (length - processed >= minimumBatchLength)
		{
			int blocks = AdvSimd.Arm64.IsSupported && length - processed < 256 ? 3 : 4;
			int batchLength = blocks * 64;
			Vector128<uint> c0 = Vector128.Create((uint)counter) + Vector128.CreateSequence(0u, 1u);
			Vector128<uint> h0 = s13;
			Vector128<uint> a00 = s00;
			Vector128<uint> a01 = s01;
			Vector128<uint> a02 = s02;
			Vector128<uint> a03 = s03;
			Vector128<uint> a04 = s04;
			Vector128<uint> a05 = s05;
			Vector128<uint> a06 = s06;
			Vector128<uint> a07 = s07;
			Vector128<uint> a08 = s08;
			Vector128<uint> a09 = s09;
			Vector128<uint> a10 = s10;
			Vector128<uint> a11 = s11;
			Vector128<uint> a12 = c0;
			Vector128<uint> a13 = h0;
			Vector128<uint> a14 = s14;
			Vector128<uint> a15 = s15;

			for (int round = 0; round < SnuffleCipher.Rounds; round += 2)
			{
				QuarterRound(ref a00, ref a04, ref a08, ref a12, ref a01, ref a05, ref a09, ref a13);
				QuarterRound(ref a02, ref a06, ref a10, ref a14, ref a03, ref a07, ref a11, ref a15);
				QuarterRound(ref a00, ref a05, ref a10, ref a15, ref a01, ref a06, ref a11, ref a12);
				QuarterRound(ref a02, ref a07, ref a08, ref a13, ref a03, ref a04, ref a09, ref a14);
			}

			a00 += s00;
			a01 += s01;
			a02 += s02;
			a03 += s03;
			a04 += s04;
			a05 += s05;
			a06 += s06;
			a07 += s07;
			a08 += s08;
			a09 += s09;
			a10 += s10;
			a11 += s11;
			a12 += c0;
			a13 += h0;
			a14 += s14;
			a15 += s15;
			bool storeFourthBlock = blocks is 4;
			VectorTranspose.TransposeXorStore(a00, a01, a02, a03, ref input, ref output, (nuint)processed, storeFourthBlock);
			VectorTranspose.TransposeXorStore(a04, a05, a06, a07, ref input, ref output, (nuint)(processed + 16), storeFourthBlock);
			VectorTranspose.TransposeXorStore(a08, a09, a10, a11, ref input, ref output, (nuint)(processed + 32), storeFourthBlock);
			VectorTranspose.TransposeXorStore(a12, a13, a14, a15, ref input, ref output, (nuint)(processed + 48), storeFourthBlock);
			counter += (uint)blocks;
			processed += batchLength;
		}

		return processed;
	}

	private static void XorVector128Two(ref uint stateRef, ref byte input, ref byte output)
	{
		ref ulong counter = ref GetCounterOriginal(ref stateRef);
		Vector128<uint> a0 = Vector128.LoadUnsafe(ref stateRef, 0);
		Vector128<uint> b0 = a0;
		Vector128<uint> a1 = Vector128.LoadUnsafe(ref stateRef, 4);
		Vector128<uint> b1 = a1;
		Vector128<uint> a2 = Vector128.LoadUnsafe(ref stateRef, 8);
		Vector128<uint> b2 = a2;
		Vector128<uint> a3 = Vector128.LoadUnsafe(ref stateRef, 12);
		Vector128<uint> b3 = a3.WithElement(0, (uint)(counter + 1));

		for (int round = 0; round < SnuffleCipher.Rounds; round += 2)
		{
			QuarterRoundLocal(ref a0, ref a1, ref a2, ref a3);
			QuarterRoundLocal(ref b0, ref b1, ref b2, ref b3);
			a0 = a0.RotateWordsLeft(3);
			a2 = a2.RotateWordsLeft(1);
			a3 = a3.RotateWordsLeft(2);
			b0 = b0.RotateWordsLeft(3);
			b2 = b2.RotateWordsLeft(1);
			b3 = b3.RotateWordsLeft(2);
			QuarterRoundLocal(ref a0, ref a1, ref a2, ref a3);
			QuarterRoundLocal(ref b0, ref b1, ref b2, ref b3);
			a0 = a0.RotateWordsLeft(1);
			a2 = a2.RotateWordsLeft(3);
			a3 = a3.RotateWordsLeft(2);
			b0 = b0.RotateWordsLeft(1);
			b2 = b2.RotateWordsLeft(3);
			b3 = b3.RotateWordsLeft(2);
		}

		a0 += Vector128.LoadUnsafe(ref stateRef, 0);
		(a0.AsByte() ^ Vector128.LoadUnsafe(ref input, 0)).StoreUnsafe(ref output, 0);
		a1 += Vector128.LoadUnsafe(ref stateRef, 4);
		(a1.AsByte() ^ Vector128.LoadUnsafe(ref input, 16)).StoreUnsafe(ref output, 16);
		a2 += Vector128.LoadUnsafe(ref stateRef, 8);
		(a2.AsByte() ^ Vector128.LoadUnsafe(ref input, 32)).StoreUnsafe(ref output, 32);
		a3 += Vector128.LoadUnsafe(ref stateRef, 12);
		(a3.AsByte() ^ Vector128.LoadUnsafe(ref input, 48)).StoreUnsafe(ref output, 48);
		b0 += Vector128.LoadUnsafe(ref stateRef, 0);
		(b0.AsByte() ^ Vector128.LoadUnsafe(ref input, 64)).StoreUnsafe(ref output, 64);
		b1 += Vector128.LoadUnsafe(ref stateRef, 4);
		(b1.AsByte() ^ Vector128.LoadUnsafe(ref input, 80)).StoreUnsafe(ref output, 80);
		b2 += Vector128.LoadUnsafe(ref stateRef, 8);
		(b2.AsByte() ^ Vector128.LoadUnsafe(ref input, 96)).StoreUnsafe(ref output, 96);
		b3 += Vector128.LoadUnsafe(ref stateRef, 12).WithElement(0, (uint)(counter + 1));
		(b3.AsByte() ^ Vector128.LoadUnsafe(ref input, 112)).StoreUnsafe(ref output, 112);
		counter += 2;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void QuarterRound(ref Vector128<uint> a, ref Vector128<uint> b, ref Vector128<uint> c, ref Vector128<uint> d, ref Vector128<uint> e, ref Vector128<uint> f, ref Vector128<uint> g, ref Vector128<uint> h)
	{
		Vector128<uint> xa = a;
		Vector128<uint> xb = b;
		Vector128<uint> xc = c;
		Vector128<uint> xd = d;
		Vector128<uint> xe = e;
		Vector128<uint> xf = f;
		Vector128<uint> xg = g;
		Vector128<uint> xh = h;
		xa += xb;
		xe += xf;
		xd = (xd ^ xa).RotateLeftUInt32(16);
		xh = (xh ^ xe).RotateLeftUInt32(16);
		xc += xd;
		xg += xh;
		xb = (xb ^ xc).RotateLeftUInt32(12);
		xf = (xf ^ xg).RotateLeftUInt32(12);
		xa += xb;
		xe += xf;
		xd = (xd ^ xa).RotateLeftUInt32(8);
		xh = (xh ^ xe).RotateLeftUInt32(8);
		xc += xd;
		xg += xh;
		xb = (xb ^ xc).RotateLeftUInt32(7);
		xf = (xf ^ xg).RotateLeftUInt32(7);
		a = xa;
		b = xb;
		c = xc;
		d = xd;
		e = xe;
		f = xf;
		g = xg;
		h = xh;
	}
}
