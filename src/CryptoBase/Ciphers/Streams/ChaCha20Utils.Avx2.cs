namespace CryptoBase.Ciphers.Streams;

internal static partial class ChaCha20Utils
{
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void QuarterRound(ref Vector256<byte> a, ref Vector256<byte> b, ref Vector256<byte> c, ref Vector256<byte> d)
	{
		a = (a.AsUInt32() + b.AsUInt32()).AsByte();
		d = (a ^ d).RotateLeftUInt32(16);

		c = (c.AsUInt32() + d.AsUInt32()).AsByte();
		b = (b ^ c).RotateLeftUInt32(12);

		a = (a.AsUInt32() + b.AsUInt32()).AsByte();
		d = (a ^ d).RotateLeftUInt32(8);

		c = (c.AsUInt32() + d.AsUInt32()).AsByte();
		b = (b ^ c).RotateLeftUInt32(7);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static void AddAndTranspose(in ulong counter, out Vector256<byte> outCounterLow, out Vector256<byte> outCounterHigh)
	{
		Vector256<uint> counterV = Vector256.Create(counter).AsUInt32();

		Vector256<uint> x0 = (counterV.AsUInt64() + Vector256.CreateSequence(0UL, 1UL)).AsUInt32();
		Vector256<uint> x1 = (counterV.AsUInt64() + Vector256.CreateSequence(4UL, 1UL)).AsUInt32();

		// =>
		// 0 8 1 9 4 12 5 13
		// 2 10 3 11 6 14 7 15
		Vector256<uint> a0 = Avx2.UnpackLow(x0, x1);
		Vector256<uint> a1 = Avx2.UnpackHigh(x0, x1);

		// =>
		// 0 2 8 10 4 6 12 14
		// 1 3 9 11 5 7 13 15
		Vector256<uint> b0 = Avx2.UnpackLow(a0, a1);
		Vector256<uint> b1 = Avx2.UnpackHigh(a0, a1);

		// =>
		// 0 2 4 6 8 10 12 14
		// 1 3 5 7 9 11 13 15
		outCounterLow = Avx2.Permute4x64(b0.AsUInt64(), 0b11_01_10_00).AsByte();
		outCounterHigh = Avx2.Permute4x64(b1.AsUInt64(), 0b11_01_10_00).AsByte();
	}

	[SkipLocalsInit]
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static int ChaChaCoreOriginal512(byte rounds, Span<uint> state, ReadOnlySpan<byte> source, Span<byte> destination)
	{
		int length = source.Length;
		int offset = 0;

		ref uint stateRef = ref state.GetReference();
		ref byte sourceRef = ref source.GetReference();
		ref byte dstRef = ref destination.GetReference();

		ref ulong counter = ref GetCounterOriginal(ref stateRef);

		Vector256<byte> o0 = Vector256.Create(Unsafe.Add(ref stateRef, 0)).AsByte();
		Vector256<byte> o1 = Vector256.Create(Unsafe.Add(ref stateRef, 1)).AsByte();
		Vector256<byte> o2 = Vector256.Create(Unsafe.Add(ref stateRef, 2)).AsByte();
		Vector256<byte> o3 = Vector256.Create(Unsafe.Add(ref stateRef, 3)).AsByte();
		Vector256<byte> o4 = Vector256.Create(Unsafe.Add(ref stateRef, 4)).AsByte();
		Vector256<byte> o5 = Vector256.Create(Unsafe.Add(ref stateRef, 5)).AsByte();
		Vector256<byte> o6 = Vector256.Create(Unsafe.Add(ref stateRef, 6)).AsByte();
		Vector256<byte> o7 = Vector256.Create(Unsafe.Add(ref stateRef, 7)).AsByte();
		Vector256<byte> o8 = Vector256.Create(Unsafe.Add(ref stateRef, 8)).AsByte();
		Vector256<byte> o9 = Vector256.Create(Unsafe.Add(ref stateRef, 9)).AsByte();
		Vector256<byte> o10 = Vector256.Create(Unsafe.Add(ref stateRef, 10)).AsByte();
		Vector256<byte> o11 = Vector256.Create(Unsafe.Add(ref stateRef, 11)).AsByte();
		// 12
		// 13
		Vector256<byte> o14 = Vector256.Create(Unsafe.Add(ref stateRef, 14)).AsByte();
		Vector256<byte> o15 = Vector256.Create(Unsafe.Add(ref stateRef, 15)).AsByte();

		while (length >= 512)
		{
			ref byte s = ref Unsafe.Add(ref sourceRef, offset);

			AddAndTranspose(counter, out Vector256<byte> o12, out Vector256<byte> o13);

			Vector256<byte> x0 = o0;
			Vector256<byte> x1 = o1;
			Vector256<byte> x2 = o2;
			Vector256<byte> x3 = o3;
			Vector256<byte> x4 = o4;
			Vector256<byte> x5 = o5;
			Vector256<byte> x6 = o6;
			Vector256<byte> x7 = o7;
			Vector256<byte> x8 = o8;
			Vector256<byte> x9 = o9;
			Vector256<byte> x10 = o10;
			Vector256<byte> x11 = o11;
			Vector256<byte> x12 = o12;
			Vector256<byte> x13 = o13;
			Vector256<byte> x14 = o14;
			Vector256<byte> x15 = o15;

			for (int i = 0; i < rounds; i += 2)
			{
				QuarterRound(ref x0, ref x4, ref x8, ref x12);
				QuarterRound(ref x1, ref x5, ref x9, ref x13);
				QuarterRound(ref x2, ref x6, ref x10, ref x14);
				QuarterRound(ref x3, ref x7, ref x11, ref x15);
				QuarterRound(ref x0, ref x5, ref x10, ref x15);
				QuarterRound(ref x1, ref x6, ref x11, ref x12);
				QuarterRound(ref x2, ref x7, ref x8, ref x13);
				QuarterRound(ref x3, ref x4, ref x9, ref x14);
			}

			x0 = (x0.AsUInt32() + o0.AsUInt32()).AsByte();
			x1 = (x1.AsUInt32() + o1.AsUInt32()).AsByte();
			x2 = (x2.AsUInt32() + o2.AsUInt32()).AsByte();
			x3 = (x3.AsUInt32() + o3.AsUInt32()).AsByte();
			x4 = (x4.AsUInt32() + o4.AsUInt32()).AsByte();
			x5 = (x5.AsUInt32() + o5.AsUInt32()).AsByte();
			x6 = (x6.AsUInt32() + o6.AsUInt32()).AsByte();
			x7 = (x7.AsUInt32() + o7.AsUInt32()).AsByte();
			x8 = (x8.AsUInt32() + o8.AsUInt32()).AsByte();
			x9 = (x9.AsUInt32() + o9.AsUInt32()).AsByte();
			x10 = (x10.AsUInt32() + o10.AsUInt32()).AsByte();
			x11 = (x11.AsUInt32() + o11.AsUInt32()).AsByte();
			x12 = (x12.AsUInt32() + o12.AsUInt32()).AsByte();
			x13 = (x13.AsUInt32() + o13.AsUInt32()).AsByte();
			x14 = (x14.AsUInt32() + o14.AsUInt32()).AsByte();
			x15 = (x15.AsUInt32() + o15.AsUInt32()).AsByte();

			VectorTranspose.Transpose(ref x0, ref x1, ref x2, ref x3, ref x4, ref x5, ref x6, ref x7, ref x8, ref x9, ref x10, ref x11, ref x12, ref x13, ref x14, ref x15);

			x0 ^= Vector256.LoadUnsafe(ref s, 0);
			x1 ^= Vector256.LoadUnsafe(ref s, 32);
			x2 ^= Vector256.LoadUnsafe(ref s, 64);
			x3 ^= Vector256.LoadUnsafe(ref s, 96);
			x4 ^= Vector256.LoadUnsafe(ref s, 128);
			x5 ^= Vector256.LoadUnsafe(ref s, 160);
			x6 ^= Vector256.LoadUnsafe(ref s, 192);
			x7 ^= Vector256.LoadUnsafe(ref s, 224);
			x8 ^= Vector256.LoadUnsafe(ref s, 256);
			x9 ^= Vector256.LoadUnsafe(ref s, 288);
			x10 ^= Vector256.LoadUnsafe(ref s, 320);
			x11 ^= Vector256.LoadUnsafe(ref s, 352);
			x12 ^= Vector256.LoadUnsafe(ref s, 384);
			x13 ^= Vector256.LoadUnsafe(ref s, 416);
			x14 ^= Vector256.LoadUnsafe(ref s, 448);
			x15 ^= Vector256.LoadUnsafe(ref s, 480);

			x0.StoreUnsafe(ref dstRef, (nuint)(offset + 0));
			x1.StoreUnsafe(ref dstRef, (nuint)(offset + 32));
			x2.StoreUnsafe(ref dstRef, (nuint)(offset + 64));
			x3.StoreUnsafe(ref dstRef, (nuint)(offset + 96));
			x4.StoreUnsafe(ref dstRef, (nuint)(offset + 128));
			x5.StoreUnsafe(ref dstRef, (nuint)(offset + 160));
			x6.StoreUnsafe(ref dstRef, (nuint)(offset + 192));
			x7.StoreUnsafe(ref dstRef, (nuint)(offset + 224));
			x8.StoreUnsafe(ref dstRef, (nuint)(offset + 256));
			x9.StoreUnsafe(ref dstRef, (nuint)(offset + 288));
			x10.StoreUnsafe(ref dstRef, (nuint)(offset + 320));
			x11.StoreUnsafe(ref dstRef, (nuint)(offset + 352));
			x12.StoreUnsafe(ref dstRef, (nuint)(offset + 384));
			x13.StoreUnsafe(ref dstRef, (nuint)(offset + 416));
			x14.StoreUnsafe(ref dstRef, (nuint)(offset + 448));
			x15.StoreUnsafe(ref dstRef, (nuint)(offset + 480));

			counter += 8;
			length -= 512;
			offset += 512;
		}

		return offset;
	}

	[SkipLocalsInit]
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static int ChaChaCore512(byte rounds, Span<uint> state, ReadOnlySpan<byte> source, Span<byte> destination)
	{
		int length = source.Length;
		int offset = 0;

		ref uint stateRef = ref state.GetReference();
		ref byte sourceRef = ref source.GetReference();
		ref byte dstRef = ref destination.GetReference();

		ref uint counter = ref GetCounter(ref stateRef);

		Vector256<byte> o0 = Vector256.Create(Unsafe.Add(ref stateRef, 0)).AsByte();
		Vector256<byte> o1 = Vector256.Create(Unsafe.Add(ref stateRef, 1)).AsByte();
		Vector256<byte> o2 = Vector256.Create(Unsafe.Add(ref stateRef, 2)).AsByte();
		Vector256<byte> o3 = Vector256.Create(Unsafe.Add(ref stateRef, 3)).AsByte();
		Vector256<byte> o4 = Vector256.Create(Unsafe.Add(ref stateRef, 4)).AsByte();
		Vector256<byte> o5 = Vector256.Create(Unsafe.Add(ref stateRef, 5)).AsByte();
		Vector256<byte> o6 = Vector256.Create(Unsafe.Add(ref stateRef, 6)).AsByte();
		Vector256<byte> o7 = Vector256.Create(Unsafe.Add(ref stateRef, 7)).AsByte();
		Vector256<byte> o8 = Vector256.Create(Unsafe.Add(ref stateRef, 8)).AsByte();
		Vector256<byte> o9 = Vector256.Create(Unsafe.Add(ref stateRef, 9)).AsByte();
		Vector256<byte> o10 = Vector256.Create(Unsafe.Add(ref stateRef, 10)).AsByte();
		Vector256<byte> o11 = Vector256.Create(Unsafe.Add(ref stateRef, 11)).AsByte();
		// 12
		Vector256<byte> o13 = Vector256.Create(Unsafe.Add(ref stateRef, 13)).AsByte();
		Vector256<byte> o14 = Vector256.Create(Unsafe.Add(ref stateRef, 14)).AsByte();
		Vector256<byte> o15 = Vector256.Create(Unsafe.Add(ref stateRef, 15)).AsByte();

		while (length >= 512)
		{
			ref byte s = ref Unsafe.Add(ref sourceRef, offset);

			Vector256<byte> o12 = Vector256.CreateSequence(counter, 1u).AsByte();
			Vector256<byte> x0 = o0;
			Vector256<byte> x1 = o1;
			Vector256<byte> x2 = o2;
			Vector256<byte> x3 = o3;
			Vector256<byte> x4 = o4;
			Vector256<byte> x5 = o5;
			Vector256<byte> x6 = o6;
			Vector256<byte> x7 = o7;
			Vector256<byte> x8 = o8;
			Vector256<byte> x9 = o9;
			Vector256<byte> x10 = o10;
			Vector256<byte> x11 = o11;
			Vector256<byte> x12 = o12;
			Vector256<byte> x13 = o13;
			Vector256<byte> x14 = o14;
			Vector256<byte> x15 = o15;

			for (int i = 0; i < rounds; i += 2)
			{
				QuarterRound(ref x0, ref x4, ref x8, ref x12);
				QuarterRound(ref x1, ref x5, ref x9, ref x13);
				QuarterRound(ref x2, ref x6, ref x10, ref x14);
				QuarterRound(ref x3, ref x7, ref x11, ref x15);
				QuarterRound(ref x0, ref x5, ref x10, ref x15);
				QuarterRound(ref x1, ref x6, ref x11, ref x12);
				QuarterRound(ref x2, ref x7, ref x8, ref x13);
				QuarterRound(ref x3, ref x4, ref x9, ref x14);
			}

			x0 = (x0.AsUInt32() + o0.AsUInt32()).AsByte();
			x1 = (x1.AsUInt32() + o1.AsUInt32()).AsByte();
			x2 = (x2.AsUInt32() + o2.AsUInt32()).AsByte();
			x3 = (x3.AsUInt32() + o3.AsUInt32()).AsByte();
			x4 = (x4.AsUInt32() + o4.AsUInt32()).AsByte();
			x5 = (x5.AsUInt32() + o5.AsUInt32()).AsByte();
			x6 = (x6.AsUInt32() + o6.AsUInt32()).AsByte();
			x7 = (x7.AsUInt32() + o7.AsUInt32()).AsByte();
			x8 = (x8.AsUInt32() + o8.AsUInt32()).AsByte();
			x9 = (x9.AsUInt32() + o9.AsUInt32()).AsByte();
			x10 = (x10.AsUInt32() + o10.AsUInt32()).AsByte();
			x11 = (x11.AsUInt32() + o11.AsUInt32()).AsByte();
			x12 = (x12.AsUInt32() + o12.AsUInt32()).AsByte();
			x13 = (x13.AsUInt32() + o13.AsUInt32()).AsByte();
			x14 = (x14.AsUInt32() + o14.AsUInt32()).AsByte();
			x15 = (x15.AsUInt32() + o15.AsUInt32()).AsByte();

			VectorTranspose.Transpose(ref x0, ref x1, ref x2, ref x3, ref x4, ref x5, ref x6, ref x7, ref x8, ref x9, ref x10, ref x11, ref x12, ref x13, ref x14, ref x15);

			x0 ^= Vector256.LoadUnsafe(ref s, 0);
			x1 ^= Vector256.LoadUnsafe(ref s, 32);
			x2 ^= Vector256.LoadUnsafe(ref s, 64);
			x3 ^= Vector256.LoadUnsafe(ref s, 96);
			x4 ^= Vector256.LoadUnsafe(ref s, 128);
			x5 ^= Vector256.LoadUnsafe(ref s, 160);
			x6 ^= Vector256.LoadUnsafe(ref s, 192);
			x7 ^= Vector256.LoadUnsafe(ref s, 224);
			x8 ^= Vector256.LoadUnsafe(ref s, 256);
			x9 ^= Vector256.LoadUnsafe(ref s, 288);
			x10 ^= Vector256.LoadUnsafe(ref s, 320);
			x11 ^= Vector256.LoadUnsafe(ref s, 352);
			x12 ^= Vector256.LoadUnsafe(ref s, 384);
			x13 ^= Vector256.LoadUnsafe(ref s, 416);
			x14 ^= Vector256.LoadUnsafe(ref s, 448);
			x15 ^= Vector256.LoadUnsafe(ref s, 480);

			x0.StoreUnsafe(ref dstRef, (nuint)(offset + 0));
			x1.StoreUnsafe(ref dstRef, (nuint)(offset + 32));
			x2.StoreUnsafe(ref dstRef, (nuint)(offset + 64));
			x3.StoreUnsafe(ref dstRef, (nuint)(offset + 96));
			x4.StoreUnsafe(ref dstRef, (nuint)(offset + 128));
			x5.StoreUnsafe(ref dstRef, (nuint)(offset + 160));
			x6.StoreUnsafe(ref dstRef, (nuint)(offset + 192));
			x7.StoreUnsafe(ref dstRef, (nuint)(offset + 224));
			x8.StoreUnsafe(ref dstRef, (nuint)(offset + 256));
			x9.StoreUnsafe(ref dstRef, (nuint)(offset + 288));
			x10.StoreUnsafe(ref dstRef, (nuint)(offset + 320));
			x11.StoreUnsafe(ref dstRef, (nuint)(offset + 352));
			x12.StoreUnsafe(ref dstRef, (nuint)(offset + 384));
			x13.StoreUnsafe(ref dstRef, (nuint)(offset + 416));
			x14.StoreUnsafe(ref dstRef, (nuint)(offset + 448));
			x15.StoreUnsafe(ref dstRef, (nuint)(offset + 480));

			counter += 8;
			length -= 512;
			offset += 512;
		}

		return offset;
	}
}
