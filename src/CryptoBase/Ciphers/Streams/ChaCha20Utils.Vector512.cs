namespace CryptoBase.Ciphers.Streams;

internal static partial class ChaCha20Utils
{
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void QuarterRound(ref Vector512<uint> a, ref Vector512<uint> b, ref Vector512<uint> c, ref Vector512<uint> d)
	{
		a += b;
		d = Avx512F.RotateLeft(d ^ a, 16);
		c += d;
		b = Avx512F.RotateLeft(b ^ c, 12);
		a += b;
		d = Avx512F.RotateLeft(d ^ a, 8);
		c += d;
		b = Avx512F.RotateLeft(b ^ c, 7);
	}

	// Runs whole 16-block batches; a shorter final batch stores only its leading blocks.
	private static void XorVector512(ref uint stateRef, ref byte input, ref byte output, int blocks)
	{
		Debug.Assert(blocks % 16 is 0 or > 8);
		ref ulong counter = ref GetCounterOriginal(ref stateRef);

		for (nuint processed = 0; blocks > 0; processed += 1024, blocks -= 16)
		{
			Vector512<uint> c0 = Vector512.Create((uint)counter) + Vector512.CreateSequence(0u, 1u);
			Vector512<uint> h0 = Vector512.Create(Unsafe.Add(ref stateRef, 13));
			Vector512<uint> a00 = Vector512.Create(Unsafe.Add(ref stateRef, 0));
			Vector512<uint> a01 = Vector512.Create(Unsafe.Add(ref stateRef, 1));
			Vector512<uint> a02 = Vector512.Create(Unsafe.Add(ref stateRef, 2));
			Vector512<uint> a03 = Vector512.Create(Unsafe.Add(ref stateRef, 3));
			Vector512<uint> a04 = Vector512.Create(Unsafe.Add(ref stateRef, 4));
			Vector512<uint> a05 = Vector512.Create(Unsafe.Add(ref stateRef, 5));
			Vector512<uint> a06 = Vector512.Create(Unsafe.Add(ref stateRef, 6));
			Vector512<uint> a07 = Vector512.Create(Unsafe.Add(ref stateRef, 7));
			Vector512<uint> a08 = Vector512.Create(Unsafe.Add(ref stateRef, 8));
			Vector512<uint> a09 = Vector512.Create(Unsafe.Add(ref stateRef, 9));
			Vector512<uint> a10 = Vector512.Create(Unsafe.Add(ref stateRef, 10));
			Vector512<uint> a11 = Vector512.Create(Unsafe.Add(ref stateRef, 11));
			Vector512<uint> a12 = c0;
			Vector512<uint> a13 = h0;
			Vector512<uint> a14 = Vector512.Create(Unsafe.Add(ref stateRef, 14));
			Vector512<uint> a15 = Vector512.Create(Unsafe.Add(ref stateRef, 15));

			for (int round = 0; round < SnuffleCipher.Rounds; round += 2)
			{
				QuarterRound(ref a00, ref a04, ref a08, ref a12);
				QuarterRound(ref a01, ref a05, ref a09, ref a13);
				QuarterRound(ref a02, ref a06, ref a10, ref a14);
				QuarterRound(ref a03, ref a07, ref a11, ref a15);
				QuarterRound(ref a00, ref a05, ref a10, ref a15);
				QuarterRound(ref a01, ref a06, ref a11, ref a12);
				QuarterRound(ref a02, ref a07, ref a08, ref a13);
				QuarterRound(ref a03, ref a04, ref a09, ref a14);
			}

			a00 += Vector512.Create(Unsafe.Add(ref stateRef, 0));
			a01 += Vector512.Create(Unsafe.Add(ref stateRef, 1));
			a02 += Vector512.Create(Unsafe.Add(ref stateRef, 2));
			a03 += Vector512.Create(Unsafe.Add(ref stateRef, 3));
			a04 += Vector512.Create(Unsafe.Add(ref stateRef, 4));
			a05 += Vector512.Create(Unsafe.Add(ref stateRef, 5));
			a06 += Vector512.Create(Unsafe.Add(ref stateRef, 6));
			a07 += Vector512.Create(Unsafe.Add(ref stateRef, 7));
			a08 += Vector512.Create(Unsafe.Add(ref stateRef, 8));
			a09 += Vector512.Create(Unsafe.Add(ref stateRef, 9));
			a10 += Vector512.Create(Unsafe.Add(ref stateRef, 10));
			a11 += Vector512.Create(Unsafe.Add(ref stateRef, 11));
			a12 += c0;
			a13 += h0;
			a14 += Vector512.Create(Unsafe.Add(ref stateRef, 14));
			a15 += Vector512.Create(Unsafe.Add(ref stateRef, 15));
			VectorTranspose.Transpose(ref a00, ref a01, ref a02, ref a03, ref a04, ref a05, ref a06, ref a07, ref a08, ref a09, ref a10, ref a11, ref a12, ref a13, ref a14, ref a15);
			(a00.AsByte() ^ Vector512.LoadUnsafe(ref input, processed)).StoreUnsafe(ref output, processed);
			(a01.AsByte() ^ Vector512.LoadUnsafe(ref input, processed + 64)).StoreUnsafe(ref output, processed + 64);
			(a02.AsByte() ^ Vector512.LoadUnsafe(ref input, processed + 128)).StoreUnsafe(ref output, processed + 128);
			(a03.AsByte() ^ Vector512.LoadUnsafe(ref input, processed + 192)).StoreUnsafe(ref output, processed + 192);
			(a04.AsByte() ^ Vector512.LoadUnsafe(ref input, processed + 256)).StoreUnsafe(ref output, processed + 256);
			(a05.AsByte() ^ Vector512.LoadUnsafe(ref input, processed + 320)).StoreUnsafe(ref output, processed + 320);
			(a06.AsByte() ^ Vector512.LoadUnsafe(ref input, processed + 384)).StoreUnsafe(ref output, processed + 384);
			(a07.AsByte() ^ Vector512.LoadUnsafe(ref input, processed + 448)).StoreUnsafe(ref output, processed + 448);
			(a08.AsByte() ^ Vector512.LoadUnsafe(ref input, processed + 512)).StoreUnsafe(ref output, processed + 512);
			if (blocks > 9)
			{
				(a09.AsByte() ^ Vector512.LoadUnsafe(ref input, processed + 576)).StoreUnsafe(ref output, processed + 576);
			}
			if (blocks > 10)
			{
				(a10.AsByte() ^ Vector512.LoadUnsafe(ref input, processed + 640)).StoreUnsafe(ref output, processed + 640);
			}
			if (blocks > 11)
			{
				(a11.AsByte() ^ Vector512.LoadUnsafe(ref input, processed + 704)).StoreUnsafe(ref output, processed + 704);
			}
			if (blocks > 12)
			{
				(a12.AsByte() ^ Vector512.LoadUnsafe(ref input, processed + 768)).StoreUnsafe(ref output, processed + 768);
			}
			if (blocks > 13)
			{
				(a13.AsByte() ^ Vector512.LoadUnsafe(ref input, processed + 832)).StoreUnsafe(ref output, processed + 832);
			}
			if (blocks > 14)
			{
				(a14.AsByte() ^ Vector512.LoadUnsafe(ref input, processed + 896)).StoreUnsafe(ref output, processed + 896);
			}
			if (blocks > 15)
			{
				(a15.AsByte() ^ Vector512.LoadUnsafe(ref input, processed + 960)).StoreUnsafe(ref output, processed + 960);
			}
			counter += (uint)Math.Min(blocks, 16);
		}
	}
}
