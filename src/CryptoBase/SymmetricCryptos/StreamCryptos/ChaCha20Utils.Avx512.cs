namespace CryptoBase.SymmetricCryptos.StreamCryptos;

internal static partial class ChaCha20Utils
{
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void QuarterRound(ref Vector512<uint> a, ref Vector512<uint> b, ref Vector512<uint> c, ref Vector512<uint> d)
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
	public static void AddAndTranspose(in ulong counter, out Vector512<uint> outCounterLow, out Vector512<uint> outCounterHigh)
	{
		Vector512<uint> counterV = Vector512.Create(counter).AsUInt32();

		Vector512<uint> x0 = (counterV.AsUInt64() + Vector512.Create(0UL, 1, 2, 3, 4, 5, 6, 7)).AsUInt32();
		Vector512<uint> x1 = (counterV.AsUInt64() + Vector512.Create(8UL, 9, 10, 11, 12, 13, 14, 15)).AsUInt32();

		outCounterLow = Avx512F.PermuteVar16x32x2(x0, Vector512.CreateSequence<uint>(0, 2), x1);
		outCounterHigh = Avx512F.PermuteVar16x32x2(x0, Vector512.CreateSequence<uint>(1, 2), x1);
	}

	public static int ChaChaCoreOriginalSoA1024Avx512(byte rounds, Span<uint> state, ReadOnlySpan<byte> source, Span<byte> destination)
	{
		int offset = 0;
		int length = source.Length;

		ref uint stateRef = ref state.GetReference();
		ref byte sourceRef = ref source.GetReference();
		ref byte dstRef = ref destination.GetReference();

		ref ulong counter = ref GetCounterOriginal(ref stateRef);

		Unsafe.SkipInit(out Vector512X16<uint> o);
		o.V0 = Vector512.Create(Unsafe.Add(ref stateRef, 0));
		o.V1 = Vector512.Create(Unsafe.Add(ref stateRef, 1));
		o.V2 = Vector512.Create(Unsafe.Add(ref stateRef, 2));
		o.V3 = Vector512.Create(Unsafe.Add(ref stateRef, 3));
		o.V4 = Vector512.Create(Unsafe.Add(ref stateRef, 4));
		o.V5 = Vector512.Create(Unsafe.Add(ref stateRef, 5));
		o.V6 = Vector512.Create(Unsafe.Add(ref stateRef, 6));
		o.V7 = Vector512.Create(Unsafe.Add(ref stateRef, 7));
		o.V8 = Vector512.Create(Unsafe.Add(ref stateRef, 8));
		o.V9 = Vector512.Create(Unsafe.Add(ref stateRef, 9));
		o.V10 = Vector512.Create(Unsafe.Add(ref stateRef, 10));
		o.V11 = Vector512.Create(Unsafe.Add(ref stateRef, 11));
		// 12
		// 13
		o.V14 = Vector512.Create(Unsafe.Add(ref stateRef, 14));
		o.V15 = Vector512.Create(Unsafe.Add(ref stateRef, 15));

		while (length >= 1024)
		{
			ref readonly Vector512X16<byte> s = ref Unsafe.As<byte, Vector512X16<byte>>(ref Unsafe.Add(ref sourceRef, offset));

			AddAndTranspose(counter, out o.V12, out o.V13);
			Vector512X16<uint> x = o;

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

			counter += 16;
			offset += 1024;
			length -= 1024;
		}

		return offset;
	}

	public static int ChaChaCoreOriginalSoA2048Avx512(byte rounds, Span<uint> state, ReadOnlySpan<byte> source, Span<byte> destination)
	{
		int offset = 0;
		int length = source.Length;

		ref uint stateRef = ref state.GetReference();
		ref byte sourceRef = ref source.GetReference();
		ref byte dstRef = ref destination.GetReference();

		ref ulong counter = ref GetCounterOriginal(ref stateRef);

		Unsafe.SkipInit(out Vector512X16<uint> o);
		o.V0 = Vector512.Create(Unsafe.Add(ref stateRef, 0));
		o.V1 = Vector512.Create(Unsafe.Add(ref stateRef, 1));
		o.V2 = Vector512.Create(Unsafe.Add(ref stateRef, 2));
		o.V3 = Vector512.Create(Unsafe.Add(ref stateRef, 3));
		o.V4 = Vector512.Create(Unsafe.Add(ref stateRef, 4));
		o.V5 = Vector512.Create(Unsafe.Add(ref stateRef, 5));
		o.V6 = Vector512.Create(Unsafe.Add(ref stateRef, 6));
		o.V7 = Vector512.Create(Unsafe.Add(ref stateRef, 7));
		o.V8 = Vector512.Create(Unsafe.Add(ref stateRef, 8));
		o.V9 = Vector512.Create(Unsafe.Add(ref stateRef, 9));
		o.V10 = Vector512.Create(Unsafe.Add(ref stateRef, 10));
		o.V11 = Vector512.Create(Unsafe.Add(ref stateRef, 11));
		// 12
		// 13
		o.V14 = Vector512.Create(Unsafe.Add(ref stateRef, 14));
		o.V15 = Vector512.Create(Unsafe.Add(ref stateRef, 15));

		while (length >= 2048)
		{
			ref readonly Vector512X16<byte> s0 = ref Unsafe.As<byte, Vector512X16<byte>>(ref Unsafe.Add(ref sourceRef, offset));
			ref readonly Vector512X16<byte> s1 = ref Unsafe.As<byte, Vector512X16<byte>>(ref Unsafe.Add(ref sourceRef, offset + 1024));

			AddAndTranspose(counter, out o.V12, out o.V13);
			Vector512<uint> t12 = o.V12;
			Vector512<uint> t13 = o.V13;
			Vector512X16<uint> x0 = o;

			AddAndTranspose(counter + 16, out o.V12, out o.V13);
			Vector512X16<uint> x1 = o;

			for (int i = 0; i < rounds; i += 2)
			{
				QuarterRound(ref x0.V0, ref x0.V4, ref x0.V8, ref x0.V12);
				QuarterRound(ref x0.V1, ref x0.V5, ref x0.V9, ref x0.V13);
				QuarterRound(ref x0.V2, ref x0.V6, ref x0.V10, ref x0.V14);
				QuarterRound(ref x0.V3, ref x0.V7, ref x0.V11, ref x0.V15);

				QuarterRound(ref x1.V0, ref x1.V4, ref x1.V8, ref x1.V12);
				QuarterRound(ref x1.V1, ref x1.V5, ref x1.V9, ref x1.V13);
				QuarterRound(ref x1.V2, ref x1.V6, ref x1.V10, ref x1.V14);
				QuarterRound(ref x1.V3, ref x1.V7, ref x1.V11, ref x1.V15);

				QuarterRound(ref x0.V0, ref x0.V5, ref x0.V10, ref x0.V15);
				QuarterRound(ref x0.V1, ref x0.V6, ref x0.V11, ref x0.V12);
				QuarterRound(ref x0.V2, ref x0.V7, ref x0.V8, ref x0.V13);
				QuarterRound(ref x0.V3, ref x0.V4, ref x0.V9, ref x0.V14);

				QuarterRound(ref x1.V0, ref x1.V5, ref x1.V10, ref x1.V15);
				QuarterRound(ref x1.V1, ref x1.V6, ref x1.V11, ref x1.V12);
				QuarterRound(ref x1.V2, ref x1.V7, ref x1.V8, ref x1.V13);
				QuarterRound(ref x1.V3, ref x1.V4, ref x1.V9, ref x1.V14);
			}

			x0.V0 += o.V0;
			x0.V1 += o.V1;
			x0.V2 += o.V2;
			x0.V3 += o.V3;
			x0.V4 += o.V4;
			x0.V5 += o.V5;
			x0.V6 += o.V6;
			x0.V7 += o.V7;
			x0.V8 += o.V8;
			x0.V9 += o.V9;
			x0.V10 += o.V10;
			x0.V11 += o.V11;
			x0.V12 += t12;
			x0.V13 += t13;
			x0.V14 += o.V14;
			x0.V15 += o.V15;
			x1.Add(o);

			x0.Transpose();
			x1.Transpose();

			x0.Xor(s0);
			x1.Xor(s1);

			Unsafe.WriteUnaligned(ref Unsafe.Add(ref dstRef, offset), x0);
			Unsafe.WriteUnaligned(ref Unsafe.Add(ref dstRef, offset + 1024), x1);

			counter += 32;
			offset += 2048;
			length -= 2048;
		}

		return offset;
	}

	public static int ChaChaCoreSoA1024Avx512(byte rounds, Span<uint> state, ReadOnlySpan<byte> source, Span<byte> destination)
	{
		int offset = 0;
		int length = source.Length;

		ref uint stateRef = ref state.GetReference();
		ref byte sourceRef = ref source.GetReference();
		ref byte dstRef = ref destination.GetReference();

		ref uint counter = ref GetCounter(ref stateRef);

		Unsafe.SkipInit(out Vector512X16<uint> o);
		o.V0 = Vector512.Create(Unsafe.Add(ref stateRef, 0));
		o.V1 = Vector512.Create(Unsafe.Add(ref stateRef, 1));
		o.V2 = Vector512.Create(Unsafe.Add(ref stateRef, 2));
		o.V3 = Vector512.Create(Unsafe.Add(ref stateRef, 3));
		o.V4 = Vector512.Create(Unsafe.Add(ref stateRef, 4));
		o.V5 = Vector512.Create(Unsafe.Add(ref stateRef, 5));
		o.V6 = Vector512.Create(Unsafe.Add(ref stateRef, 6));
		o.V7 = Vector512.Create(Unsafe.Add(ref stateRef, 7));
		o.V8 = Vector512.Create(Unsafe.Add(ref stateRef, 8));
		o.V9 = Vector512.Create(Unsafe.Add(ref stateRef, 9));
		o.V10 = Vector512.Create(Unsafe.Add(ref stateRef, 10));
		o.V11 = Vector512.Create(Unsafe.Add(ref stateRef, 11));
		// 12
		o.V13 = Vector512.Create(Unsafe.Add(ref stateRef, 13));
		o.V14 = Vector512.Create(Unsafe.Add(ref stateRef, 14));
		o.V15 = Vector512.Create(Unsafe.Add(ref stateRef, 15));

		while (length >= 1024)
		{
			ref readonly Vector512X16<byte> s = ref Unsafe.As<byte, Vector512X16<byte>>(ref Unsafe.Add(ref sourceRef, offset));

			o.V12 = Vector512.Create(counter) + Vector512.CreateSequence<uint>(0, 1);
			Vector512X16<uint> x = o;

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

			counter += 16;
			offset += 1024;
			length -= 1024;
		}

		return offset;
	}

	public static int ChaChaCoreSoA2048Avx512(byte rounds, Span<uint> state, ReadOnlySpan<byte> source, Span<byte> destination)
	{
		int offset = 0;
		int length = source.Length;

		ref uint stateRef = ref state.GetReference();
		ref byte sourceRef = ref source.GetReference();
		ref byte dstRef = ref destination.GetReference();

		ref uint counter = ref GetCounter(ref stateRef);

		Unsafe.SkipInit(out Vector512X16<uint> o);
		o.V0 = Vector512.Create(Unsafe.Add(ref stateRef, 0));
		o.V1 = Vector512.Create(Unsafe.Add(ref stateRef, 1));
		o.V2 = Vector512.Create(Unsafe.Add(ref stateRef, 2));
		o.V3 = Vector512.Create(Unsafe.Add(ref stateRef, 3));
		o.V4 = Vector512.Create(Unsafe.Add(ref stateRef, 4));
		o.V5 = Vector512.Create(Unsafe.Add(ref stateRef, 5));
		o.V6 = Vector512.Create(Unsafe.Add(ref stateRef, 6));
		o.V7 = Vector512.Create(Unsafe.Add(ref stateRef, 7));
		o.V8 = Vector512.Create(Unsafe.Add(ref stateRef, 8));
		o.V9 = Vector512.Create(Unsafe.Add(ref stateRef, 9));
		o.V10 = Vector512.Create(Unsafe.Add(ref stateRef, 10));
		o.V11 = Vector512.Create(Unsafe.Add(ref stateRef, 11));
		// 12
		o.V13 = Vector512.Create(Unsafe.Add(ref stateRef, 13));
		o.V14 = Vector512.Create(Unsafe.Add(ref stateRef, 14));
		o.V15 = Vector512.Create(Unsafe.Add(ref stateRef, 15));

		while (length >= 2048)
		{
			ref readonly Vector512X16<byte> s0 = ref Unsafe.As<byte, Vector512X16<byte>>(ref Unsafe.Add(ref sourceRef, offset));
			ref readonly Vector512X16<byte> s1 = ref Unsafe.As<byte, Vector512X16<byte>>(ref Unsafe.Add(ref sourceRef, offset + 1024));

			Vector512<uint> t12 = o.V12 = Vector512.Create(counter) + Vector512.CreateSequence<uint>(0, 1);
			Vector512X16<uint> x0 = o;
			o.V12 = Vector512.Create(counter + 16) + Vector512.CreateSequence<uint>(0, 1);
			Vector512X16<uint> x1 = o;

			for (int i = 0; i < rounds; i += 2)
			{
				QuarterRound(ref x0.V0, ref x0.V4, ref x0.V8, ref x0.V12);
				QuarterRound(ref x0.V1, ref x0.V5, ref x0.V9, ref x0.V13);
				QuarterRound(ref x0.V2, ref x0.V6, ref x0.V10, ref x0.V14);
				QuarterRound(ref x0.V3, ref x0.V7, ref x0.V11, ref x0.V15);

				QuarterRound(ref x1.V0, ref x1.V4, ref x1.V8, ref x1.V12);
				QuarterRound(ref x1.V1, ref x1.V5, ref x1.V9, ref x1.V13);
				QuarterRound(ref x1.V2, ref x1.V6, ref x1.V10, ref x1.V14);
				QuarterRound(ref x1.V3, ref x1.V7, ref x1.V11, ref x1.V15);

				QuarterRound(ref x0.V0, ref x0.V5, ref x0.V10, ref x0.V15);
				QuarterRound(ref x0.V1, ref x0.V6, ref x0.V11, ref x0.V12);
				QuarterRound(ref x0.V2, ref x0.V7, ref x0.V8, ref x0.V13);
				QuarterRound(ref x0.V3, ref x0.V4, ref x0.V9, ref x0.V14);

				QuarterRound(ref x1.V0, ref x1.V5, ref x1.V10, ref x1.V15);
				QuarterRound(ref x1.V1, ref x1.V6, ref x1.V11, ref x1.V12);
				QuarterRound(ref x1.V2, ref x1.V7, ref x1.V8, ref x1.V13);
				QuarterRound(ref x1.V3, ref x1.V4, ref x1.V9, ref x1.V14);
			}

			x0.V0 += o.V0;
			x0.V1 += o.V1;
			x0.V2 += o.V2;
			x0.V3 += o.V3;
			x0.V4 += o.V4;
			x0.V5 += o.V5;
			x0.V6 += o.V6;
			x0.V7 += o.V7;
			x0.V8 += o.V8;
			x0.V9 += o.V9;
			x0.V10 += o.V10;
			x0.V11 += o.V11;
			x0.V12 += t12;
			x0.V13 += o.V13;
			x0.V14 += o.V14;
			x0.V15 += o.V15;
			x1.Add(o);

			x0.Transpose();
			x1.Transpose();

			x0.Xor(s0);
			x1.Xor(s1);

			Unsafe.WriteUnaligned(ref Unsafe.Add(ref dstRef, offset), x0);
			Unsafe.WriteUnaligned(ref Unsafe.Add(ref dstRef, offset + 1024), x1);

			counter += 32;
			offset += 2048;
			length -= 2048;
		}

		return offset;
	}
}
