namespace CryptoBase.SymmetricCryptos.StreamCryptos;

internal static partial class ChaCha20Utils
{
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void QuarterRound(ref Vector256<uint> a, ref Vector256<uint> b, ref Vector256<uint> c, ref Vector256<uint> d)
	{
		a += b;
		d = (a ^ d).RotateLeftUInt32_16();

		c += d;
		b = (b ^ c).RotateLeftUInt32(12);

		a += b;
		d = (a ^ d).RotateLeftUInt32_8();

		c += d;
		b = (b ^ c).RotateLeftUInt32(7);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static void AddAndTranspose(in ulong counter, out Vector256<uint> outCounterLow, out Vector256<uint> outCounterHigh)
	{
		Vector256<uint> counterV = Vector256.Create(counter).AsUInt32();

		Vector256<uint> x0 = (counterV.AsUInt64() + Vector256.Create(0UL, 1, 2, 3)).AsUInt32();
		Vector256<uint> x1 = (counterV.AsUInt64() + Vector256.Create(4UL, 5, 6, 7)).AsUInt32();

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
		Vector256<uint> control = Vector256.Create(0u, 1, 4, 5, 2, 3, 6, 7);
		outCounterLow = Avx2.PermuteVar8x32(b0, control);
		outCounterHigh = Avx2.PermuteVar8x32(b1, control);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static int ChaChaCoreOriginal512(byte rounds, Span<uint> state, ReadOnlySpan<byte> source, Span<byte> destination)
	{
		int length = source.Length;
		int offset = 0;

		ref uint stateRef = ref state.GetReference();
		ref byte sourceRef = ref source.GetReference();
		ref byte dstRef = ref destination.GetReference();

		ref ulong counter = ref GetCounterOriginal(ref stateRef);

		Unsafe.SkipInit(out Vector256X16<uint> o);
		o.V0 = Vector256.Create(Unsafe.Add(ref stateRef, 0));
		o.V1 = Vector256.Create(Unsafe.Add(ref stateRef, 1));
		o.V2 = Vector256.Create(Unsafe.Add(ref stateRef, 2));
		o.V3 = Vector256.Create(Unsafe.Add(ref stateRef, 3));
		o.V4 = Vector256.Create(Unsafe.Add(ref stateRef, 4));
		o.V5 = Vector256.Create(Unsafe.Add(ref stateRef, 5));
		o.V6 = Vector256.Create(Unsafe.Add(ref stateRef, 6));
		o.V7 = Vector256.Create(Unsafe.Add(ref stateRef, 7));
		o.V8 = Vector256.Create(Unsafe.Add(ref stateRef, 8));
		o.V9 = Vector256.Create(Unsafe.Add(ref stateRef, 9));
		o.V10 = Vector256.Create(Unsafe.Add(ref stateRef, 10));
		o.V11 = Vector256.Create(Unsafe.Add(ref stateRef, 11));
		// 12
		// 13
		o.V14 = Vector256.Create(Unsafe.Add(ref stateRef, 14));
		o.V15 = Vector256.Create(Unsafe.Add(ref stateRef, 15));

		while (length >= 512)
		{
			ref readonly Vector256X16<byte> s = ref Unsafe.As<byte, Vector256X16<byte>>(ref Unsafe.Add(ref sourceRef, offset));

			AddAndTranspose(counter, out o.V12, out o.V13);

			Vector256X16<uint> x = o;

			for (int i = 0; i < rounds; i += 2)
			{
				QuarterRound(ref x.V0, ref x.V4, ref x.V8, ref x.V12);
				QuarterRound(ref x.V1, ref x.V5, ref x.V9, ref x.V13);
				QuarterRound(ref x.V2, ref x.V6, ref x.V10, ref x.V14);
				QuarterRound(ref x.V3, ref x.V7, ref x.V11, ref x.V15);
				QuarterRound(ref x.V0, ref x.V5, ref x.V10, ref x.V15);
				QuarterRound(ref x.V1, ref x.V6, ref x.V11, ref x.V12);
				QuarterRound(ref x.V2, ref x.V7, ref x.V8, ref x.V13);
				QuarterRound(ref x.V3, ref x.V4, ref x.V9, ref x.V14);
			}

			x.Add(o);
			x.Transpose();
			x.Xor(s);

			Unsafe.WriteUnaligned(ref Unsafe.Add(ref dstRef, offset), x);

			counter += 8;
			length -= 512;
			offset += 512;
		}

		return offset;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static int ChaChaCore512(byte rounds, Span<uint> state, ReadOnlySpan<byte> source, Span<byte> destination)
	{
		int length = source.Length;
		int offset = 0;

		ref uint stateRef = ref state.GetReference();
		ref byte sourceRef = ref source.GetReference();
		ref byte dstRef = ref destination.GetReference();

		ref uint counter = ref GetCounter(ref stateRef);

		Unsafe.SkipInit(out Vector256X16<uint> o);
		o.V0 = Vector256.Create(Unsafe.Add(ref stateRef, 0));
		o.V1 = Vector256.Create(Unsafe.Add(ref stateRef, 1));
		o.V2 = Vector256.Create(Unsafe.Add(ref stateRef, 2));
		o.V3 = Vector256.Create(Unsafe.Add(ref stateRef, 3));
		o.V4 = Vector256.Create(Unsafe.Add(ref stateRef, 4));
		o.V5 = Vector256.Create(Unsafe.Add(ref stateRef, 5));
		o.V6 = Vector256.Create(Unsafe.Add(ref stateRef, 6));
		o.V7 = Vector256.Create(Unsafe.Add(ref stateRef, 7));
		o.V8 = Vector256.Create(Unsafe.Add(ref stateRef, 8));
		o.V9 = Vector256.Create(Unsafe.Add(ref stateRef, 9));
		o.V10 = Vector256.Create(Unsafe.Add(ref stateRef, 10));
		o.V11 = Vector256.Create(Unsafe.Add(ref stateRef, 11));
		// 12
		o.V13 = Vector256.Create(Unsafe.Add(ref stateRef, 13));
		o.V14 = Vector256.Create(Unsafe.Add(ref stateRef, 14));
		o.V15 = Vector256.Create(Unsafe.Add(ref stateRef, 15));

		while (length >= 512)
		{
			ref readonly Vector256X16<byte> s = ref Unsafe.As<byte, Vector256X16<byte>>(ref Unsafe.Add(ref sourceRef, offset));

			o.V12 = Vector256.Create(counter) + Vector256.Create(0u, 1, 2, 3, 4, 5, 6, 7);
			Vector256X16<uint> x = o;

			for (int i = 0; i < rounds; i += 2)
			{
				QuarterRound(ref x.V0, ref x.V4, ref x.V8, ref x.V12);
				QuarterRound(ref x.V1, ref x.V5, ref x.V9, ref x.V13);
				QuarterRound(ref x.V2, ref x.V6, ref x.V10, ref x.V14);
				QuarterRound(ref x.V3, ref x.V7, ref x.V11, ref x.V15);
				QuarterRound(ref x.V0, ref x.V5, ref x.V10, ref x.V15);
				QuarterRound(ref x.V1, ref x.V6, ref x.V11, ref x.V12);
				QuarterRound(ref x.V2, ref x.V7, ref x.V8, ref x.V13);
				QuarterRound(ref x.V3, ref x.V4, ref x.V9, ref x.V14);
			}

			x.Add(o);
			x.Transpose();
			x.Xor(s);

			Unsafe.WriteUnaligned(ref Unsafe.Add(ref dstRef, offset), x);

			counter += 8;
			length -= 512;
			offset += 512;
		}

		return offset;
	}
}
