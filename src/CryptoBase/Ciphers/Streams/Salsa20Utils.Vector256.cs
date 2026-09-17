namespace CryptoBase.Ciphers.Streams;

internal static partial class Salsa20Utils
{
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void QuarterRound(ref Vector256<uint> a, ref Vector256<uint> b, ref Vector256<uint> c, ref Vector256<uint> d)
	{
		Vector256<uint> x = a;
		Vector256<uint> y = b;
		Vector256<uint> z = c;
		Vector256<uint> w = d;
		x ^= (y + z).RotateLeftUInt32(7);
		w ^= (x + y).RotateLeftUInt32(9);
		z ^= (w + x).RotateLeftUInt32(13);
		y ^= (z + w).RotateLeftUInt32(18);
		a = x;
		b = y;
		c = z;
		d = w;
	}

	private static int XorVector256(ref uint stateRef, ref byte input, ref byte output, int length)
	{
		ref ulong counter = ref GetCounter(ref stateRef);
		int processed = 0;
		uint s15 = Unsafe.Add(ref stateRef, 15);

		while (length - processed >= 512)
		{
			Vector256<uint> c0 = Vector256.Create((uint)counter) + Vector256.CreateSequence(0u, 1u);
			Vector256<uint> h0 = Vector256.Create(Unsafe.Add(ref stateRef, 9));
			Vector256<uint> a00 = Vector256.Create(Unsafe.Add(ref stateRef, 0));
			Vector256<uint> a01 = Vector256.Create(Unsafe.Add(ref stateRef, 1));
			Vector256<uint> a02 = Vector256.Create(Unsafe.Add(ref stateRef, 2));
			Vector256<uint> a03 = Vector256.Create(Unsafe.Add(ref stateRef, 3));
			Vector256<uint> a04 = Vector256.Create(Unsafe.Add(ref stateRef, 4));
			Vector256<uint> a05 = Vector256.Create(Unsafe.Add(ref stateRef, 5));
			Vector256<uint> a06 = Vector256.Create(Unsafe.Add(ref stateRef, 6));
			Vector256<uint> a07 = Vector256.Create(Unsafe.Add(ref stateRef, 7));
			Vector256<uint> a08 = c0;
			Vector256<uint> a09 = h0;
			Vector256<uint> a10 = Vector256.Create(Unsafe.Add(ref stateRef, 10));
			Vector256<uint> a11 = Vector256.Create(Unsafe.Add(ref stateRef, 11));
			Vector256<uint> a12 = Vector256.Create(Unsafe.Add(ref stateRef, 12));
			Vector256<uint> a13 = Vector256.Create(Unsafe.Add(ref stateRef, 13));
			Vector256<uint> a14 = Vector256.Create(Unsafe.Add(ref stateRef, 14));
			Vector256<uint> a15 = Vector256.Create(s15);

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

			a00 += Vector256.Create(Unsafe.Add(ref stateRef, 0));
			a01 += Vector256.Create(Unsafe.Add(ref stateRef, 1));
			a02 += Vector256.Create(Unsafe.Add(ref stateRef, 2));
			a03 += Vector256.Create(Unsafe.Add(ref stateRef, 3));
			a04 += Vector256.Create(Unsafe.Add(ref stateRef, 4));
			a05 += Vector256.Create(Unsafe.Add(ref stateRef, 5));
			a06 += Vector256.Create(Unsafe.Add(ref stateRef, 6));
			a07 += Vector256.Create(Unsafe.Add(ref stateRef, 7));
			a08 += c0;
			a09 += h0;
			a10 += Vector256.Create(Unsafe.Add(ref stateRef, 10));
			a11 += Vector256.Create(Unsafe.Add(ref stateRef, 11));
			a12 += Vector256.Create(Unsafe.Add(ref stateRef, 12));
			a13 += Vector256.Create(Unsafe.Add(ref stateRef, 13));
			a14 += Vector256.Create(Unsafe.Add(ref stateRef, 14));
			a15 += Vector256.Create(s15);
			VectorTranspose.Transpose(ref a00, ref a01, ref a02, ref a03, ref a04, ref a05, ref a06, ref a07, ref a08, ref a09, ref a10, ref a11, ref a12, ref a13, ref a14, ref a15);
			(a00.AsByte() ^ Vector256.LoadUnsafe(ref input, (nuint)processed)).StoreUnsafe(ref output, (nuint)processed);
			(a01.AsByte() ^ Vector256.LoadUnsafe(ref input, (nuint)(processed + 32))).StoreUnsafe(ref output, (nuint)(processed + 32));
			(a02.AsByte() ^ Vector256.LoadUnsafe(ref input, (nuint)(processed + 64))).StoreUnsafe(ref output, (nuint)(processed + 64));
			(a03.AsByte() ^ Vector256.LoadUnsafe(ref input, (nuint)(processed + 96))).StoreUnsafe(ref output, (nuint)(processed + 96));
			(a04.AsByte() ^ Vector256.LoadUnsafe(ref input, (nuint)(processed + 128))).StoreUnsafe(ref output, (nuint)(processed + 128));
			(a05.AsByte() ^ Vector256.LoadUnsafe(ref input, (nuint)(processed + 160))).StoreUnsafe(ref output, (nuint)(processed + 160));
			(a06.AsByte() ^ Vector256.LoadUnsafe(ref input, (nuint)(processed + 192))).StoreUnsafe(ref output, (nuint)(processed + 192));
			(a07.AsByte() ^ Vector256.LoadUnsafe(ref input, (nuint)(processed + 224))).StoreUnsafe(ref output, (nuint)(processed + 224));
			(a08.AsByte() ^ Vector256.LoadUnsafe(ref input, (nuint)(processed + 256))).StoreUnsafe(ref output, (nuint)(processed + 256));
			(a09.AsByte() ^ Vector256.LoadUnsafe(ref input, (nuint)(processed + 288))).StoreUnsafe(ref output, (nuint)(processed + 288));
			(a10.AsByte() ^ Vector256.LoadUnsafe(ref input, (nuint)(processed + 320))).StoreUnsafe(ref output, (nuint)(processed + 320));
			(a11.AsByte() ^ Vector256.LoadUnsafe(ref input, (nuint)(processed + 352))).StoreUnsafe(ref output, (nuint)(processed + 352));
			(a12.AsByte() ^ Vector256.LoadUnsafe(ref input, (nuint)(processed + 384))).StoreUnsafe(ref output, (nuint)(processed + 384));
			(a13.AsByte() ^ Vector256.LoadUnsafe(ref input, (nuint)(processed + 416))).StoreUnsafe(ref output, (nuint)(processed + 416));
			(a14.AsByte() ^ Vector256.LoadUnsafe(ref input, (nuint)(processed + 448))).StoreUnsafe(ref output, (nuint)(processed + 448));
			(a15.AsByte() ^ Vector256.LoadUnsafe(ref input, (nuint)(processed + 480))).StoreUnsafe(ref output, (nuint)(processed + 480));
			counter += 8;
			processed += 512;
		}

		return processed;
	}
}
