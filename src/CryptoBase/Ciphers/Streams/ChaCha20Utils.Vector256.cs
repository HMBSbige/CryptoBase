namespace CryptoBase.Ciphers.Streams;

internal static partial class ChaCha20Utils
{
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void QuarterRound(ref Vector256<uint> a, ref Vector256<uint> b, ref Vector256<uint> c, ref Vector256<uint> d)
	{
		a += b;
		d = (d ^ a).RotateLeftUInt32(16);
		c += d;
		b = (b ^ c).RotateLeftUInt32(12);
		a += b;
		d = (d ^ a).RotateLeftUInt32(8);
		c += d;
		b = (b ^ c).RotateLeftUInt32(7);
	}

	private static int XorVector256(ref uint stateRef, ref byte input, ref byte output, int length)
	{
		ref ulong counter = ref GetCounterOriginal(ref stateRef);
		int processed = 0;

		while (length - processed >= 512)
		{
			Vector256<uint> c0 = Vector256.Create((uint)counter) + Vector256.CreateSequence(0u, 1u);
			Vector256<uint> h0 = Vector256.Create(Unsafe.Add(ref stateRef, 13));
			Vector256<uint> a00 = Vector256.Create(Unsafe.Add(ref stateRef, 0));
			Vector256<uint> a01 = Vector256.Create(Unsafe.Add(ref stateRef, 1));
			Vector256<uint> a02 = Vector256.Create(Unsafe.Add(ref stateRef, 2));
			Vector256<uint> a03 = Vector256.Create(Unsafe.Add(ref stateRef, 3));
			Vector256<uint> a04 = Vector256.Create(Unsafe.Add(ref stateRef, 4));
			Vector256<uint> a05 = Vector256.Create(Unsafe.Add(ref stateRef, 5));
			Vector256<uint> a06 = Vector256.Create(Unsafe.Add(ref stateRef, 6));
			Vector256<uint> a07 = Vector256.Create(Unsafe.Add(ref stateRef, 7));
			Vector256<uint> a08 = Vector256.Create(Unsafe.Add(ref stateRef, 8));
			Vector256<uint> a09 = Vector256.Create(Unsafe.Add(ref stateRef, 9));
			Vector256<uint> a10 = Vector256.Create(Unsafe.Add(ref stateRef, 10));
			Vector256<uint> a11 = Vector256.Create(Unsafe.Add(ref stateRef, 11));
			Vector256<uint> a12 = c0;
			Vector256<uint> a13 = h0;
			Vector256<uint> a14 = Vector256.Create(Unsafe.Add(ref stateRef, 14));
			Vector256<uint> a15 = Vector256.Create(Unsafe.Add(ref stateRef, 15));

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

			a00 += Vector256.Create(Unsafe.Add(ref stateRef, 0));
			a01 += Vector256.Create(Unsafe.Add(ref stateRef, 1));
			a02 += Vector256.Create(Unsafe.Add(ref stateRef, 2));
			a03 += Vector256.Create(Unsafe.Add(ref stateRef, 3));
			a04 += Vector256.Create(Unsafe.Add(ref stateRef, 4));
			a05 += Vector256.Create(Unsafe.Add(ref stateRef, 5));
			a06 += Vector256.Create(Unsafe.Add(ref stateRef, 6));
			a07 += Vector256.Create(Unsafe.Add(ref stateRef, 7));
			a08 += Vector256.Create(Unsafe.Add(ref stateRef, 8));
			a09 += Vector256.Create(Unsafe.Add(ref stateRef, 9));
			a10 += Vector256.Create(Unsafe.Add(ref stateRef, 10));
			a11 += Vector256.Create(Unsafe.Add(ref stateRef, 11));
			a12 += c0;
			a13 += h0;
			a14 += Vector256.Create(Unsafe.Add(ref stateRef, 14));
			a15 += Vector256.Create(Unsafe.Add(ref stateRef, 15));
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

	private static void XorVector256Four(ref uint stateRef, ref byte input, ref byte output)
	{
		Vector128<uint> row = Vector128.LoadUnsafe(ref stateRef);
		Vector256<uint> a0 = Vector256.Create(row);
		Vector256<uint> b0 = a0;
		row = Vector128.LoadUnsafe(ref stateRef, 4);
		Vector256<uint> a1 = Vector256.Create(row);
		Vector256<uint> b1 = a1;
		row = Vector128.LoadUnsafe(ref stateRef, 8);
		Vector256<uint> a2 = Vector256.Create(row);
		Vector256<uint> b2 = a2;
		row = Vector128.LoadUnsafe(ref stateRef, 12);
		Vector256<uint> a3 = Vector256.Create(row).AddUInt32LE01();
		Vector256<uint> b3 = a3.AddUInt32LE22();

		for (int round = 0; round < SnuffleCipher.Rounds; round += 2)
		{
			QuarterRound(ref a0, ref a1, ref a2, ref a3, ref b0, ref b1, ref b2, ref b3);
			a0 = Avx2.Shuffle(a0, 0b10_01_00_11);
			a2 = Avx2.Shuffle(a2, 0b00_11_10_01);
			a3 = Avx2.Shuffle(a3, 0b01_00_11_10);
			b0 = Avx2.Shuffle(b0, 0b10_01_00_11);
			b2 = Avx2.Shuffle(b2, 0b00_11_10_01);
			b3 = Avx2.Shuffle(b3, 0b01_00_11_10);
			QuarterRound(ref a0, ref a1, ref a2, ref a3, ref b0, ref b1, ref b2, ref b3);
			a0 = Avx2.Shuffle(a0, 0b00_11_10_01);
			a2 = Avx2.Shuffle(a2, 0b10_01_00_11);
			a3 = Avx2.Shuffle(a3, 0b01_00_11_10);
			b0 = Avx2.Shuffle(b0, 0b00_11_10_01);
			b2 = Avx2.Shuffle(b2, 0b10_01_00_11);
			b3 = Avx2.Shuffle(b3, 0b01_00_11_10);
		}

		row = Vector128.LoadUnsafe(ref stateRef);
		Vector256<uint> initial = Vector256.Create(row);
		a0 += initial;
		b0 += initial;
		row = Vector128.LoadUnsafe(ref stateRef, 4);
		initial = Vector256.Create(row);
		a1 += initial;
		b1 += initial;
		row = Vector128.LoadUnsafe(ref stateRef, 8);
		initial = Vector256.Create(row);
		a2 += initial;
		b2 += initial;
		row = Vector128.LoadUnsafe(ref stateRef, 12);
		initial = Vector256.Create(row).AddUInt32LE01();
		a3 += initial;
		b3 += initial.AddUInt32LE22();
		(Avx2.Permute2x128(a0, a1, 0x20).AsByte() ^ Vector256.LoadUnsafe(ref input)).StoreUnsafe(ref output);
		(Avx2.Permute2x128(a2, a3, 0x20).AsByte() ^ Vector256.LoadUnsafe(ref input, 32)).StoreUnsafe(ref output, 32);
		(Avx2.Permute2x128(a0, a1, 0x31).AsByte() ^ Vector256.LoadUnsafe(ref input, 64)).StoreUnsafe(ref output, 64);
		(Avx2.Permute2x128(a2, a3, 0x31).AsByte() ^ Vector256.LoadUnsafe(ref input, 96)).StoreUnsafe(ref output, 96);
		(Avx2.Permute2x128(b0, b1, 0x20).AsByte() ^ Vector256.LoadUnsafe(ref input, 128)).StoreUnsafe(ref output, 128);
		(Avx2.Permute2x128(b2, b3, 0x20).AsByte() ^ Vector256.LoadUnsafe(ref input, 160)).StoreUnsafe(ref output, 160);
		(Avx2.Permute2x128(b0, b1, 0x31).AsByte() ^ Vector256.LoadUnsafe(ref input, 192)).StoreUnsafe(ref output, 192);
		(Avx2.Permute2x128(b2, b3, 0x31).AsByte() ^ Vector256.LoadUnsafe(ref input, 224)).StoreUnsafe(ref output, 224);
		GetCounterOriginal(ref stateRef) += 4;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void QuarterRound(ref Vector256<uint> a, ref Vector256<uint> b, ref Vector256<uint> c, ref Vector256<uint> d, ref Vector256<uint> e, ref Vector256<uint> f, ref Vector256<uint> g, ref Vector256<uint> h)
	{
		a += b;
		e += f;
		d = (d ^ a).RotateLeftUInt32(16);
		h = (h ^ e).RotateLeftUInt32(16);
		c += d;
		g += h;
		b = (b ^ c).RotateLeftUInt32(12);
		f = (f ^ g).RotateLeftUInt32(12);
		a += b;
		e += f;
		d = (d ^ a).RotateLeftUInt32(8);
		h = (h ^ e).RotateLeftUInt32(8);
		c += d;
		g += h;
		b = (b ^ c).RotateLeftUInt32(7);
		f = (f ^ g).RotateLeftUInt32(7);
	}
}
