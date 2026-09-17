namespace CryptoBase.Ciphers.Streams;

internal static partial class Salsa20Utils
{
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void QuarterRound(ref Vector512<uint> a, ref Vector512<uint> b, ref Vector512<uint> c, ref Vector512<uint> d)
	{
		a ^= (b + c).RotateLeftUInt32(7);
		d ^= (a + b).RotateLeftUInt32(9);
		c ^= (d + a).RotateLeftUInt32(13);
		b ^= (c + d).RotateLeftUInt32(18);
	}

	private static int XorVector512(ref uint stateRef, ref byte input, ref byte output, int length)
	{
		ref ulong counter = ref GetCounter(ref stateRef);
		int processed = 0;
		uint s15 = Unsafe.Add(ref stateRef, 15);

		while (length - processed >= 1024)
		{
			Vector512<uint> c0 = Vector512.Create((uint)counter) + Vector512.CreateSequence(0u, 1u);
			Vector512<uint> h0 = Vector512.Create(Unsafe.Add(ref stateRef, 9));
			Vector512<uint> a00 = Vector512.Create(Unsafe.Add(ref stateRef, 0));
			Vector512<uint> a01 = Vector512.Create(Unsafe.Add(ref stateRef, 1));
			Vector512<uint> a02 = Vector512.Create(Unsafe.Add(ref stateRef, 2));
			Vector512<uint> a03 = Vector512.Create(Unsafe.Add(ref stateRef, 3));
			Vector512<uint> a04 = Vector512.Create(Unsafe.Add(ref stateRef, 4));
			Vector512<uint> a05 = Vector512.Create(Unsafe.Add(ref stateRef, 5));
			Vector512<uint> a06 = Vector512.Create(Unsafe.Add(ref stateRef, 6));
			Vector512<uint> a07 = Vector512.Create(Unsafe.Add(ref stateRef, 7));
			Vector512<uint> a08 = c0;
			Vector512<uint> a09 = h0;
			Vector512<uint> a10 = Vector512.Create(Unsafe.Add(ref stateRef, 10));
			Vector512<uint> a11 = Vector512.Create(Unsafe.Add(ref stateRef, 11));
			Vector512<uint> a12 = Vector512.Create(Unsafe.Add(ref stateRef, 12));
			Vector512<uint> a13 = Vector512.Create(Unsafe.Add(ref stateRef, 13));
			Vector512<uint> a14 = Vector512.Create(Unsafe.Add(ref stateRef, 14));
			Vector512<uint> a15 = Vector512.Create(s15);

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

			a00 += Vector512.Create(Unsafe.Add(ref stateRef, 0));
			a01 += Vector512.Create(Unsafe.Add(ref stateRef, 1));
			a02 += Vector512.Create(Unsafe.Add(ref stateRef, 2));
			a03 += Vector512.Create(Unsafe.Add(ref stateRef, 3));
			a04 += Vector512.Create(Unsafe.Add(ref stateRef, 4));
			a05 += Vector512.Create(Unsafe.Add(ref stateRef, 5));
			a06 += Vector512.Create(Unsafe.Add(ref stateRef, 6));
			a07 += Vector512.Create(Unsafe.Add(ref stateRef, 7));
			a08 += c0;
			a09 += h0;
			a10 += Vector512.Create(Unsafe.Add(ref stateRef, 10));
			a11 += Vector512.Create(Unsafe.Add(ref stateRef, 11));
			a12 += Vector512.Create(Unsafe.Add(ref stateRef, 12));
			a13 += Vector512.Create(Unsafe.Add(ref stateRef, 13));
			a14 += Vector512.Create(Unsafe.Add(ref stateRef, 14));
			a15 += Vector512.Create(s15);
			VectorTranspose.Transpose(ref a00, ref a01, ref a02, ref a03, ref a04, ref a05, ref a06, ref a07, ref a08, ref a09, ref a10, ref a11, ref a12, ref a13, ref a14, ref a15);
			(a00.AsByte() ^ Vector512.LoadUnsafe(ref input, (nuint)processed)).StoreUnsafe(ref output, (nuint)processed);
			(a01.AsByte() ^ Vector512.LoadUnsafe(ref input, (nuint)(processed + 64))).StoreUnsafe(ref output, (nuint)(processed + 64));
			(a02.AsByte() ^ Vector512.LoadUnsafe(ref input, (nuint)(processed + 128))).StoreUnsafe(ref output, (nuint)(processed + 128));
			(a03.AsByte() ^ Vector512.LoadUnsafe(ref input, (nuint)(processed + 192))).StoreUnsafe(ref output, (nuint)(processed + 192));
			(a04.AsByte() ^ Vector512.LoadUnsafe(ref input, (nuint)(processed + 256))).StoreUnsafe(ref output, (nuint)(processed + 256));
			(a05.AsByte() ^ Vector512.LoadUnsafe(ref input, (nuint)(processed + 320))).StoreUnsafe(ref output, (nuint)(processed + 320));
			(a06.AsByte() ^ Vector512.LoadUnsafe(ref input, (nuint)(processed + 384))).StoreUnsafe(ref output, (nuint)(processed + 384));
			(a07.AsByte() ^ Vector512.LoadUnsafe(ref input, (nuint)(processed + 448))).StoreUnsafe(ref output, (nuint)(processed + 448));
			(a08.AsByte() ^ Vector512.LoadUnsafe(ref input, (nuint)(processed + 512))).StoreUnsafe(ref output, (nuint)(processed + 512));
			(a09.AsByte() ^ Vector512.LoadUnsafe(ref input, (nuint)(processed + 576))).StoreUnsafe(ref output, (nuint)(processed + 576));
			(a10.AsByte() ^ Vector512.LoadUnsafe(ref input, (nuint)(processed + 640))).StoreUnsafe(ref output, (nuint)(processed + 640));
			(a11.AsByte() ^ Vector512.LoadUnsafe(ref input, (nuint)(processed + 704))).StoreUnsafe(ref output, (nuint)(processed + 704));
			(a12.AsByte() ^ Vector512.LoadUnsafe(ref input, (nuint)(processed + 768))).StoreUnsafe(ref output, (nuint)(processed + 768));
			(a13.AsByte() ^ Vector512.LoadUnsafe(ref input, (nuint)(processed + 832))).StoreUnsafe(ref output, (nuint)(processed + 832));
			(a14.AsByte() ^ Vector512.LoadUnsafe(ref input, (nuint)(processed + 896))).StoreUnsafe(ref output, (nuint)(processed + 896));
			(a15.AsByte() ^ Vector512.LoadUnsafe(ref input, (nuint)(processed + 960))).StoreUnsafe(ref output, (nuint)(processed + 960));
			counter += 16;
			processed += 1024;
		}

		return processed;
	}
}
