namespace CryptoBase.Ciphers.Streams;

internal static partial class Salsa20Utils
{
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void QuarterRound(ref Vector128<uint> a, ref Vector128<uint> b, ref Vector128<uint> c, ref Vector128<uint> d)
	{
		Vector128<uint> x = a;
		Vector128<uint> y = b;
		Vector128<uint> z = c;
		Vector128<uint> w = d;
		Vector128<uint> sum = y + z;
		x ^= sum.RotateLeftUInt32(7);
		sum = x + y;
		w ^= sum.RotateLeftUInt32(9);
		sum = w + x;
		z ^= sum.RotateLeftUInt32(13);
		sum = z + w;
		y ^= sum.RotateLeftUInt32(18);
		a = x;
		b = y;
		c = z;
		d = w;
	}

	// a: [0, 1, 2, 3], b: [4, 5, 6, 7], c: [8, 9, 10, 11]
	// => a: [5, 6, 7, 4], b: [3, 0, 1, 2], c: [10, 11, 8, 9]
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void Shuffle(ref Vector128<uint> a, ref Vector128<uint> b, ref Vector128<uint> c)
	{
		(a, b) = (b, a);
		a = a.RotateWordsLeft(1);
		b = b.RotateWordsLeft(3);
		c = c.RotateWordsLeft(2);
	}

	// a: [4, 9, 14, 3], b: [0, 5, 10, 15], c: [12, 1, 6, 11], d: [8, 13, 2, 7]
	// => a: [0, 1, 2, 3], b: [4, 5, 6, 7], c: [8, 9, 10, 11], d: [12, 13, 14, 15]
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void Shuffle(ref Vector128<uint> a, ref Vector128<uint> b, ref Vector128<uint> c, ref Vector128<uint> d)
	{
		a = a.RotateWordsLeft(3);
		c = c.RotateWordsLeft(1);
		d = d.RotateWordsLeft(2);

		Vector128<uint> t0 = VectorTranspose.ZipLow(b, c);
		Vector128<uint> t1 = VectorTranspose.ZipLow(d, a);
		Vector128<uint> t2 = VectorTranspose.ZipHigh(b, c);
		Vector128<uint> t3 = VectorTranspose.ZipHigh(d, a);

		a = VectorTranspose.ZipLow(t0.AsUInt64(), t1.AsUInt64()).AsUInt32();
		b = Vector128.Shuffle(VectorTranspose.ZipHigh(t0, t1), Vector128.Create(3u, 0, 2, 1));
		c = VectorTranspose.ZipLow(t3.AsUInt64(), t2.AsUInt64()).AsUInt32();
		d = Vector128.Shuffle(VectorTranspose.ZipHigh(t2, t3), Vector128.Create(2u, 1, 3, 0));
	}

	private static int XorVector128(ref uint stateRef, ref byte input, ref byte output, int length)
	{
		ref ulong counter = ref GetCounter(ref stateRef);
		int processed = 0;
		uint s15 = Unsafe.Add(ref stateRef, 15);
		int minimumBatchLength = AdvSimd.Arm64.IsSupported ? 192 : 256;

		while (length - processed >= minimumBatchLength)
		{
			int blocks = AdvSimd.Arm64.IsSupported && length - processed < 256 ? 3 : 4;
			int batchLength = blocks * 64;
			Vector128<uint> c0 = Vector128.Create((uint)counter) + Vector128.CreateSequence(0u, 1u);
			Vector128<uint> h0 = Vector128.Create(Unsafe.Add(ref stateRef, 9));
			Vector128<uint> a00 = Vector128.Create(Unsafe.Add(ref stateRef, 0));
			Vector128<uint> a01 = Vector128.Create(Unsafe.Add(ref stateRef, 1));
			Vector128<uint> a02 = Vector128.Create(Unsafe.Add(ref stateRef, 2));
			Vector128<uint> a03 = Vector128.Create(Unsafe.Add(ref stateRef, 3));
			Vector128<uint> a04 = Vector128.Create(Unsafe.Add(ref stateRef, 4));
			Vector128<uint> a05 = Vector128.Create(Unsafe.Add(ref stateRef, 5));
			Vector128<uint> a06 = Vector128.Create(Unsafe.Add(ref stateRef, 6));
			Vector128<uint> a07 = Vector128.Create(Unsafe.Add(ref stateRef, 7));
			Vector128<uint> a08 = c0;
			Vector128<uint> a09 = h0;
			Vector128<uint> a10 = Vector128.Create(Unsafe.Add(ref stateRef, 10));
			Vector128<uint> a11 = Vector128.Create(Unsafe.Add(ref stateRef, 11));
			Vector128<uint> a12 = Vector128.Create(Unsafe.Add(ref stateRef, 12));
			Vector128<uint> a13 = Vector128.Create(Unsafe.Add(ref stateRef, 13));
			Vector128<uint> a14 = Vector128.Create(Unsafe.Add(ref stateRef, 14));
			Vector128<uint> a15 = Vector128.Create(s15);

			for (int round = 0; round < SnuffleCipher.Rounds; round += 2)
			{
				QuarterRound(ref a04, ref a00, ref a12, ref a08);
				QuarterRound(ref a09, ref a05, ref a01, ref a13);
				QuarterRound(ref a14, ref a10, ref a06, ref a02);
				QuarterRound(ref a03, ref a15, ref a11, ref a07);
				QuarterRound(ref a01, ref a00, ref a03, ref a02);
				QuarterRound(ref a06, ref a05, ref a04, ref a07);
				QuarterRound(ref a11, ref a10, ref a09, ref a08);
				QuarterRound(ref a12, ref a15, ref a14, ref a13);
			}

			a00 += Vector128.Create(Unsafe.Add(ref stateRef, 0));
			a01 += Vector128.Create(Unsafe.Add(ref stateRef, 1));
			a02 += Vector128.Create(Unsafe.Add(ref stateRef, 2));
			a03 += Vector128.Create(Unsafe.Add(ref stateRef, 3));
			a04 += Vector128.Create(Unsafe.Add(ref stateRef, 4));
			a05 += Vector128.Create(Unsafe.Add(ref stateRef, 5));
			a06 += Vector128.Create(Unsafe.Add(ref stateRef, 6));
			a07 += Vector128.Create(Unsafe.Add(ref stateRef, 7));
			a08 += c0;
			a09 += h0;
			a10 += Vector128.Create(Unsafe.Add(ref stateRef, 10));
			a11 += Vector128.Create(Unsafe.Add(ref stateRef, 11));
			a12 += Vector128.Create(Unsafe.Add(ref stateRef, 12));
			a13 += Vector128.Create(Unsafe.Add(ref stateRef, 13));
			a14 += Vector128.Create(Unsafe.Add(ref stateRef, 14));
			a15 += Vector128.Create(s15);
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
		ref ulong counter = ref GetCounter(ref stateRef);
		Vector128<uint> s0 = Vector128.LoadUnsafe(ref stateRef, 0);
		Vector128<uint> s1 = Vector128.LoadUnsafe(ref stateRef, 4);
		Vector128<uint> s2 = Vector128.LoadUnsafe(ref stateRef, 8);
		Vector128<uint> s3 = Vector128.LoadUnsafe(ref stateRef, 12);
		Vector128<uint> a1 = s0;
		Vector128<uint> a2 = s1.RotateWordsLeft(1);
		Vector128<uint> a3 = s2.RotateWordsLeft(2);
		Vector128<uint> a0 = s3.RotateWordsLeft(3);
		Vector128<uint> t0 = VectorTranspose.ZipLow(a1, a2);
		Vector128<uint> t1 = VectorTranspose.ZipHigh(a1, a2);
		Vector128<uint> t2 = VectorTranspose.ZipLow(a3, a0);
		Vector128<uint> t3 = VectorTranspose.ZipHigh(a3, a0);
		a1 = VectorTranspose.ZipLow(t0.AsUInt64(), t2.AsUInt64()).AsUInt32();
		a2 = Vector128.Create(t0.GetUpper(), t2.GetUpper()).RotateWordsLeft(3);
		a3 = VectorTranspose.ZipLow(t1.AsUInt64(), t3.AsUInt64()).AsUInt32().RotateWordsLeft(2);
		a0 = Vector128.Create(t1.GetUpper(), t3.GetUpper()).RotateWordsLeft(1);
		Vector128<uint> b0 = a0;
		Vector128<uint> b1 = a1;
		Vector128<uint> b2 = a2;
		Vector128<uint> b3 = a3.WithElement(0, (uint)(counter + 1));

		for (int round = 0; round < SnuffleCipher.Rounds; round += 2)
		{
			QuarterRound(ref a0, ref a1, ref a2, ref a3);
			QuarterRound(ref b0, ref b1, ref b2, ref b3);
			Shuffle(ref a0, ref a2, ref a3);
			Shuffle(ref b0, ref b2, ref b3);
			QuarterRound(ref a0, ref a1, ref a2, ref a3);
			QuarterRound(ref b0, ref b1, ref b2, ref b3);
			Shuffle(ref a0, ref a2, ref a3);
			Shuffle(ref b0, ref b2, ref b3);
		}

		Shuffle(ref a0, ref a1, ref a2, ref a3);
		Shuffle(ref b0, ref b1, ref b2, ref b3);
		a0 += s0;
		(a0.AsByte() ^ Vector128.LoadUnsafe(ref input, 0)).StoreUnsafe(ref output, 0);
		a1 += s1;
		(a1.AsByte() ^ Vector128.LoadUnsafe(ref input, 16)).StoreUnsafe(ref output, 16);
		a2 += s2;
		(a2.AsByte() ^ Vector128.LoadUnsafe(ref input, 32)).StoreUnsafe(ref output, 32);
		a3 += s3;
		(a3.AsByte() ^ Vector128.LoadUnsafe(ref input, 48)).StoreUnsafe(ref output, 48);
		b0 += s0;
		(b0.AsByte() ^ Vector128.LoadUnsafe(ref input, 64)).StoreUnsafe(ref output, 64);
		b1 += s1;
		(b1.AsByte() ^ Vector128.LoadUnsafe(ref input, 80)).StoreUnsafe(ref output, 80);
		b2 += s2.WithElement(0, (uint)(counter + 1));
		(b2.AsByte() ^ Vector128.LoadUnsafe(ref input, 96)).StoreUnsafe(ref output, 96);
		b3 += s3;
		(b3.AsByte() ^ Vector128.LoadUnsafe(ref input, 112)).StoreUnsafe(ref output, 112);
		counter += 2;
	}
}
