namespace CryptoBase.SymmetricCryptos.StreamCryptos;

internal static partial class ChaCha20Utils
{
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void QuarterRound(ref Vector512<byte> a, ref Vector512<byte> b, ref Vector512<byte> c, ref Vector512<byte> d)
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
	public static void AddAndTranspose(in ulong counter, out Vector512<byte> outCounterLow, out Vector512<byte> outCounterHigh)
	{
		Vector512<uint> counterV = Vector512.Create(counter).AsUInt32();

		Vector512<uint> x0 = (counterV.AsUInt64() + Vector512.Create(0UL, 1, 2, 3, 4, 5, 6, 7)).AsUInt32();
		Vector512<uint> x1 = (counterV.AsUInt64() + Vector512.Create(8UL, 9, 10, 11, 12, 13, 14, 15)).AsUInt32();

		outCounterLow = Avx512F.PermuteVar16x32x2(x0, Vector512.CreateSequence<uint>(0, 2), x1).AsByte();
		outCounterHigh = Avx512F.PermuteVar16x32x2(x0, Vector512.CreateSequence<uint>(1, 2), x1).AsByte();
	}

	public static int ChaChaCoreOriginalSoA1024Avx512(byte rounds, Span<uint> state, ReadOnlySpan<byte> source, Span<byte> destination)
	{
		int offset = 0;
		int length = source.Length;

		ref uint stateRef = ref state.GetReference();
		ref byte sourceRef = ref source.GetReference();
		ref byte dstRef = ref destination.GetReference();

		ref ulong counter = ref GetCounterOriginal(ref stateRef);

		Unsafe.SkipInit(out VectorBuffer1024 o);
		o.V512_0 = Vector512.Create(Unsafe.Add(ref stateRef, 0)).AsByte();
		o.V512_1 = Vector512.Create(Unsafe.Add(ref stateRef, 1)).AsByte();
		o.V512_2 = Vector512.Create(Unsafe.Add(ref stateRef, 2)).AsByte();
		o.V512_3 = Vector512.Create(Unsafe.Add(ref stateRef, 3)).AsByte();
		o.V512_4 = Vector512.Create(Unsafe.Add(ref stateRef, 4)).AsByte();
		o.V512_5 = Vector512.Create(Unsafe.Add(ref stateRef, 5)).AsByte();
		o.V512_6 = Vector512.Create(Unsafe.Add(ref stateRef, 6)).AsByte();
		o.V512_7 = Vector512.Create(Unsafe.Add(ref stateRef, 7)).AsByte();
		o.V512_8 = Vector512.Create(Unsafe.Add(ref stateRef, 8)).AsByte();
		o.V512_9 = Vector512.Create(Unsafe.Add(ref stateRef, 9)).AsByte();
		o.V512_10 = Vector512.Create(Unsafe.Add(ref stateRef, 10)).AsByte();
		o.V512_11 = Vector512.Create(Unsafe.Add(ref stateRef, 11)).AsByte();
		// 12
		// 13
		o.V512_14 = Vector512.Create(Unsafe.Add(ref stateRef, 14)).AsByte();
		o.V512_15 = Vector512.Create(Unsafe.Add(ref stateRef, 15)).AsByte();

		while (length >= 1024)
		{
			ref readonly VectorBuffer1024 s = ref Unsafe.As<byte, VectorBuffer1024>(ref Unsafe.Add(ref sourceRef, offset));

			AddAndTranspose(counter, out o.V512_12, out o.V512_13);
			VectorBuffer1024 x = o;

			for (int i = 0; i < rounds; i += 2)
			{
				QuarterRound(ref x.V512_0, ref x.V512_4, ref x.V512_8, ref x.V512_12);
				QuarterRound(ref x.V512_1, ref x.V512_5, ref x.V512_9, ref x.V512_13);
				QuarterRound(ref x.V512_2, ref x.V512_6, ref x.V512_10, ref x.V512_14);
				QuarterRound(ref x.V512_3, ref x.V512_7, ref x.V512_11, ref x.V512_15);
				QuarterRound(ref x.V512_0, ref x.V512_5, ref x.V512_10, ref x.V512_15);
				QuarterRound(ref x.V512_1, ref x.V512_6, ref x.V512_11, ref x.V512_12);
				QuarterRound(ref x.V512_2, ref x.V512_7, ref x.V512_8, ref x.V512_13);
				QuarterRound(ref x.V512_3, ref x.V512_4, ref x.V512_9, ref x.V512_14);
			}

			x.V512_0 = (x.V512_0.AsUInt32() + o.V512_0.AsUInt32()).AsByte();
			x.V512_1 = (x.V512_1.AsUInt32() + o.V512_1.AsUInt32()).AsByte();
			x.V512_2 = (x.V512_2.AsUInt32() + o.V512_2.AsUInt32()).AsByte();
			x.V512_3 = (x.V512_3.AsUInt32() + o.V512_3.AsUInt32()).AsByte();
			x.V512_4 = (x.V512_4.AsUInt32() + o.V512_4.AsUInt32()).AsByte();
			x.V512_5 = (x.V512_5.AsUInt32() + o.V512_5.AsUInt32()).AsByte();
			x.V512_6 = (x.V512_6.AsUInt32() + o.V512_6.AsUInt32()).AsByte();
			x.V512_7 = (x.V512_7.AsUInt32() + o.V512_7.AsUInt32()).AsByte();
			x.V512_8 = (x.V512_8.AsUInt32() + o.V512_8.AsUInt32()).AsByte();
			x.V512_9 = (x.V512_9.AsUInt32() + o.V512_9.AsUInt32()).AsByte();
			x.V512_10 = (x.V512_10.AsUInt32() + o.V512_10.AsUInt32()).AsByte();
			x.V512_11 = (x.V512_11.AsUInt32() + o.V512_11.AsUInt32()).AsByte();
			x.V512_12 = (x.V512_12.AsUInt32() + o.V512_12.AsUInt32()).AsByte();
			x.V512_13 = (x.V512_13.AsUInt32() + o.V512_13.AsUInt32()).AsByte();
			x.V512_14 = (x.V512_14.AsUInt32() + o.V512_14.AsUInt32()).AsByte();
			x.V512_15 = (x.V512_15.AsUInt32() + o.V512_15.AsUInt32()).AsByte();

			x.Transpose();

			x.V512_0 ^= s.V512_0;
			x.V512_1 ^= s.V512_1;
			x.V512_2 ^= s.V512_2;
			x.V512_3 ^= s.V512_3;
			x.V512_4 ^= s.V512_4;
			x.V512_5 ^= s.V512_5;
			x.V512_6 ^= s.V512_6;
			x.V512_7 ^= s.V512_7;
			x.V512_8 ^= s.V512_8;
			x.V512_9 ^= s.V512_9;
			x.V512_10 ^= s.V512_10;
			x.V512_11 ^= s.V512_11;
			x.V512_12 ^= s.V512_12;
			x.V512_13 ^= s.V512_13;
			x.V512_14 ^= s.V512_14;
			x.V512_15 ^= s.V512_15;

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

		Unsafe.SkipInit(out VectorBuffer1024 o);
		o.V512_0 = Vector512.Create(Unsafe.Add(ref stateRef, 0)).AsByte();
		o.V512_1 = Vector512.Create(Unsafe.Add(ref stateRef, 1)).AsByte();
		o.V512_2 = Vector512.Create(Unsafe.Add(ref stateRef, 2)).AsByte();
		o.V512_3 = Vector512.Create(Unsafe.Add(ref stateRef, 3)).AsByte();
		o.V512_4 = Vector512.Create(Unsafe.Add(ref stateRef, 4)).AsByte();
		o.V512_5 = Vector512.Create(Unsafe.Add(ref stateRef, 5)).AsByte();
		o.V512_6 = Vector512.Create(Unsafe.Add(ref stateRef, 6)).AsByte();
		o.V512_7 = Vector512.Create(Unsafe.Add(ref stateRef, 7)).AsByte();
		o.V512_8 = Vector512.Create(Unsafe.Add(ref stateRef, 8)).AsByte();
		o.V512_9 = Vector512.Create(Unsafe.Add(ref stateRef, 9)).AsByte();
		o.V512_10 = Vector512.Create(Unsafe.Add(ref stateRef, 10)).AsByte();
		o.V512_11 = Vector512.Create(Unsafe.Add(ref stateRef, 11)).AsByte();
		// 12
		// 13
		o.V512_14 = Vector512.Create(Unsafe.Add(ref stateRef, 14)).AsByte();
		o.V512_15 = Vector512.Create(Unsafe.Add(ref stateRef, 15)).AsByte();

		while (length >= 2048)
		{
			ref readonly VectorBuffer1024 s0 = ref Unsafe.As<byte, VectorBuffer1024>(ref Unsafe.Add(ref sourceRef, offset));
			ref readonly VectorBuffer1024 s1 = ref Unsafe.As<byte, VectorBuffer1024>(ref Unsafe.Add(ref sourceRef, offset + 1024));

			AddAndTranspose(counter, out o.V512_12, out o.V512_13);
			Vector512<uint> t12 = o.V512_12.AsUInt32();
			Vector512<uint> t13 = o.V512_13.AsUInt32();
			VectorBuffer1024 x0 = o;

			AddAndTranspose(counter + 16, out o.V512_12, out o.V512_13);
			VectorBuffer1024 x1 = o;

			for (int i = 0; i < rounds; i += 2)
			{
				QuarterRound(ref x0.V512_0, ref x0.V512_4, ref x0.V512_8, ref x0.V512_12);
				QuarterRound(ref x0.V512_1, ref x0.V512_5, ref x0.V512_9, ref x0.V512_13);
				QuarterRound(ref x0.V512_2, ref x0.V512_6, ref x0.V512_10, ref x0.V512_14);
				QuarterRound(ref x0.V512_3, ref x0.V512_7, ref x0.V512_11, ref x0.V512_15);

				QuarterRound(ref x1.V512_0, ref x1.V512_4, ref x1.V512_8, ref x1.V512_12);
				QuarterRound(ref x1.V512_1, ref x1.V512_5, ref x1.V512_9, ref x1.V512_13);
				QuarterRound(ref x1.V512_2, ref x1.V512_6, ref x1.V512_10, ref x1.V512_14);
				QuarterRound(ref x1.V512_3, ref x1.V512_7, ref x1.V512_11, ref x1.V512_15);

				QuarterRound(ref x0.V512_0, ref x0.V512_5, ref x0.V512_10, ref x0.V512_15);
				QuarterRound(ref x0.V512_1, ref x0.V512_6, ref x0.V512_11, ref x0.V512_12);
				QuarterRound(ref x0.V512_2, ref x0.V512_7, ref x0.V512_8, ref x0.V512_13);
				QuarterRound(ref x0.V512_3, ref x0.V512_4, ref x0.V512_9, ref x0.V512_14);

				QuarterRound(ref x1.V512_0, ref x1.V512_5, ref x1.V512_10, ref x1.V512_15);
				QuarterRound(ref x1.V512_1, ref x1.V512_6, ref x1.V512_11, ref x1.V512_12);
				QuarterRound(ref x1.V512_2, ref x1.V512_7, ref x1.V512_8, ref x1.V512_13);
				QuarterRound(ref x1.V512_3, ref x1.V512_4, ref x1.V512_9, ref x1.V512_14);
			}

			x0.V512_0 = (x0.V512_0.AsUInt32() + o.V512_0.AsUInt32()).AsByte();
			x1.V512_0 = (x1.V512_0.AsUInt32() + o.V512_0.AsUInt32()).AsByte();
			x0.V512_1 = (x0.V512_1.AsUInt32() + o.V512_1.AsUInt32()).AsByte();
			x1.V512_1 = (x1.V512_1.AsUInt32() + o.V512_1.AsUInt32()).AsByte();
			x0.V512_2 = (x0.V512_2.AsUInt32() + o.V512_2.AsUInt32()).AsByte();
			x1.V512_2 = (x1.V512_2.AsUInt32() + o.V512_2.AsUInt32()).AsByte();
			x0.V512_3 = (x0.V512_3.AsUInt32() + o.V512_3.AsUInt32()).AsByte();
			x1.V512_3 = (x1.V512_3.AsUInt32() + o.V512_3.AsUInt32()).AsByte();
			x0.V512_4 = (x0.V512_4.AsUInt32() + o.V512_4.AsUInt32()).AsByte();
			x1.V512_4 = (x1.V512_4.AsUInt32() + o.V512_4.AsUInt32()).AsByte();
			x0.V512_5 = (x0.V512_5.AsUInt32() + o.V512_5.AsUInt32()).AsByte();
			x1.V512_5 = (x1.V512_5.AsUInt32() + o.V512_5.AsUInt32()).AsByte();
			x0.V512_6 = (x0.V512_6.AsUInt32() + o.V512_6.AsUInt32()).AsByte();
			x1.V512_6 = (x1.V512_6.AsUInt32() + o.V512_6.AsUInt32()).AsByte();
			x0.V512_7 = (x0.V512_7.AsUInt32() + o.V512_7.AsUInt32()).AsByte();
			x1.V512_7 = (x1.V512_7.AsUInt32() + o.V512_7.AsUInt32()).AsByte();
			x0.V512_8 = (x0.V512_8.AsUInt32() + o.V512_8.AsUInt32()).AsByte();
			x1.V512_8 = (x1.V512_8.AsUInt32() + o.V512_8.AsUInt32()).AsByte();
			x0.V512_9 = (x0.V512_9.AsUInt32() + o.V512_9.AsUInt32()).AsByte();
			x1.V512_9 = (x1.V512_9.AsUInt32() + o.V512_9.AsUInt32()).AsByte();
			x0.V512_10 = (x0.V512_10.AsUInt32() + o.V512_10.AsUInt32()).AsByte();
			x1.V512_10 = (x1.V512_10.AsUInt32() + o.V512_10.AsUInt32()).AsByte();
			x0.V512_11 = (x0.V512_11.AsUInt32() + o.V512_11.AsUInt32()).AsByte();
			x1.V512_11 = (x1.V512_11.AsUInt32() + o.V512_11.AsUInt32()).AsByte();
			x0.V512_12 = (x0.V512_12.AsUInt32() + t12).AsByte();
			x1.V512_12 = (x1.V512_12.AsUInt32() + o.V512_12.AsUInt32()).AsByte();
			x0.V512_13 = (x0.V512_13.AsUInt32() + t13).AsByte();
			x1.V512_13 = (x1.V512_13.AsUInt32() + o.V512_13.AsUInt32()).AsByte();
			x0.V512_14 = (x0.V512_14.AsUInt32() + o.V512_14.AsUInt32()).AsByte();
			x1.V512_14 = (x1.V512_14.AsUInt32() + o.V512_14.AsUInt32()).AsByte();
			x0.V512_15 = (x0.V512_15.AsUInt32() + o.V512_15.AsUInt32()).AsByte();
			x1.V512_15 = (x1.V512_15.AsUInt32() + o.V512_15.AsUInt32()).AsByte();

			x0.Transpose();
			x1.Transpose();

			x0.V512_0 ^= s0.V512_0;
			x1.V512_0 ^= s1.V512_0;
			x0.V512_1 ^= s0.V512_1;
			x1.V512_1 ^= s1.V512_1;
			x0.V512_2 ^= s0.V512_2;
			x1.V512_2 ^= s1.V512_2;
			x0.V512_3 ^= s0.V512_3;
			x1.V512_3 ^= s1.V512_3;
			x0.V512_4 ^= s0.V512_4;
			x1.V512_4 ^= s1.V512_4;
			x0.V512_5 ^= s0.V512_5;
			x1.V512_5 ^= s1.V512_5;
			x0.V512_6 ^= s0.V512_6;
			x1.V512_6 ^= s1.V512_6;
			x0.V512_7 ^= s0.V512_7;
			x1.V512_7 ^= s1.V512_7;
			x0.V512_8 ^= s0.V512_8;
			x1.V512_8 ^= s1.V512_8;
			x0.V512_9 ^= s0.V512_9;
			x1.V512_9 ^= s1.V512_9;
			x0.V512_10 ^= s0.V512_10;
			x1.V512_10 ^= s1.V512_10;
			x0.V512_11 ^= s0.V512_11;
			x1.V512_11 ^= s1.V512_11;
			x0.V512_12 ^= s0.V512_12;
			x1.V512_12 ^= s1.V512_12;
			x0.V512_13 ^= s0.V512_13;
			x1.V512_13 ^= s1.V512_13;
			x0.V512_14 ^= s0.V512_14;
			x1.V512_14 ^= s1.V512_14;
			x0.V512_15 ^= s0.V512_15;
			x1.V512_15 ^= s1.V512_15;

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

		Unsafe.SkipInit(out VectorBuffer1024 o);
		o.V512_0 = Vector512.Create(Unsafe.Add(ref stateRef, 0)).AsByte();
		o.V512_1 = Vector512.Create(Unsafe.Add(ref stateRef, 1)).AsByte();
		o.V512_2 = Vector512.Create(Unsafe.Add(ref stateRef, 2)).AsByte();
		o.V512_3 = Vector512.Create(Unsafe.Add(ref stateRef, 3)).AsByte();
		o.V512_4 = Vector512.Create(Unsafe.Add(ref stateRef, 4)).AsByte();
		o.V512_5 = Vector512.Create(Unsafe.Add(ref stateRef, 5)).AsByte();
		o.V512_6 = Vector512.Create(Unsafe.Add(ref stateRef, 6)).AsByte();
		o.V512_7 = Vector512.Create(Unsafe.Add(ref stateRef, 7)).AsByte();
		o.V512_8 = Vector512.Create(Unsafe.Add(ref stateRef, 8)).AsByte();
		o.V512_9 = Vector512.Create(Unsafe.Add(ref stateRef, 9)).AsByte();
		o.V512_10 = Vector512.Create(Unsafe.Add(ref stateRef, 10)).AsByte();
		o.V512_11 = Vector512.Create(Unsafe.Add(ref stateRef, 11)).AsByte();
		// 12
		o.V512_13 = Vector512.Create(Unsafe.Add(ref stateRef, 13)).AsByte();
		o.V512_14 = Vector512.Create(Unsafe.Add(ref stateRef, 14)).AsByte();
		o.V512_15 = Vector512.Create(Unsafe.Add(ref stateRef, 15)).AsByte();

		while (length >= 1024)
		{
			ref readonly VectorBuffer1024 s = ref Unsafe.As<byte, VectorBuffer1024>(ref Unsafe.Add(ref sourceRef, offset));

			o.V512_12 = (Vector512.Create(counter) + Vector512.CreateSequence<uint>(0, 1)).AsByte();
			VectorBuffer1024 x = o;

			for (int i = 0; i < rounds; i += 2)
			{
				QuarterRound(ref x.V512_0, ref x.V512_4, ref x.V512_8, ref x.V512_12);
				QuarterRound(ref x.V512_1, ref x.V512_5, ref x.V512_9, ref x.V512_13);
				QuarterRound(ref x.V512_2, ref x.V512_6, ref x.V512_10, ref x.V512_14);
				QuarterRound(ref x.V512_3, ref x.V512_7, ref x.V512_11, ref x.V512_15);
				QuarterRound(ref x.V512_0, ref x.V512_5, ref x.V512_10, ref x.V512_15);
				QuarterRound(ref x.V512_1, ref x.V512_6, ref x.V512_11, ref x.V512_12);
				QuarterRound(ref x.V512_2, ref x.V512_7, ref x.V512_8, ref x.V512_13);
				QuarterRound(ref x.V512_3, ref x.V512_4, ref x.V512_9, ref x.V512_14);
			}

			x.V512_0 = (x.V512_0.AsUInt32() + o.V512_0.AsUInt32()).AsByte();
			x.V512_1 = (x.V512_1.AsUInt32() + o.V512_1.AsUInt32()).AsByte();
			x.V512_2 = (x.V512_2.AsUInt32() + o.V512_2.AsUInt32()).AsByte();
			x.V512_3 = (x.V512_3.AsUInt32() + o.V512_3.AsUInt32()).AsByte();
			x.V512_4 = (x.V512_4.AsUInt32() + o.V512_4.AsUInt32()).AsByte();
			x.V512_5 = (x.V512_5.AsUInt32() + o.V512_5.AsUInt32()).AsByte();
			x.V512_6 = (x.V512_6.AsUInt32() + o.V512_6.AsUInt32()).AsByte();
			x.V512_7 = (x.V512_7.AsUInt32() + o.V512_7.AsUInt32()).AsByte();
			x.V512_8 = (x.V512_8.AsUInt32() + o.V512_8.AsUInt32()).AsByte();
			x.V512_9 = (x.V512_9.AsUInt32() + o.V512_9.AsUInt32()).AsByte();
			x.V512_10 = (x.V512_10.AsUInt32() + o.V512_10.AsUInt32()).AsByte();
			x.V512_11 = (x.V512_11.AsUInt32() + o.V512_11.AsUInt32()).AsByte();
			x.V512_12 = (x.V512_12.AsUInt32() + o.V512_12.AsUInt32()).AsByte();
			x.V512_13 = (x.V512_13.AsUInt32() + o.V512_13.AsUInt32()).AsByte();
			x.V512_14 = (x.V512_14.AsUInt32() + o.V512_14.AsUInt32()).AsByte();
			x.V512_15 = (x.V512_15.AsUInt32() + o.V512_15.AsUInt32()).AsByte();

			x.Transpose();

			x.V512_0 ^= s.V512_0;
			x.V512_1 ^= s.V512_1;
			x.V512_2 ^= s.V512_2;
			x.V512_3 ^= s.V512_3;
			x.V512_4 ^= s.V512_4;
			x.V512_5 ^= s.V512_5;
			x.V512_6 ^= s.V512_6;
			x.V512_7 ^= s.V512_7;
			x.V512_8 ^= s.V512_8;
			x.V512_9 ^= s.V512_9;
			x.V512_10 ^= s.V512_10;
			x.V512_11 ^= s.V512_11;
			x.V512_12 ^= s.V512_12;
			x.V512_13 ^= s.V512_13;
			x.V512_14 ^= s.V512_14;
			x.V512_15 ^= s.V512_15;

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

		Unsafe.SkipInit(out VectorBuffer1024 o);
		o.V512_0 = Vector512.Create(Unsafe.Add(ref stateRef, 0)).AsByte();
		o.V512_1 = Vector512.Create(Unsafe.Add(ref stateRef, 1)).AsByte();
		o.V512_2 = Vector512.Create(Unsafe.Add(ref stateRef, 2)).AsByte();
		o.V512_3 = Vector512.Create(Unsafe.Add(ref stateRef, 3)).AsByte();
		o.V512_4 = Vector512.Create(Unsafe.Add(ref stateRef, 4)).AsByte();
		o.V512_5 = Vector512.Create(Unsafe.Add(ref stateRef, 5)).AsByte();
		o.V512_6 = Vector512.Create(Unsafe.Add(ref stateRef, 6)).AsByte();
		o.V512_7 = Vector512.Create(Unsafe.Add(ref stateRef, 7)).AsByte();
		o.V512_8 = Vector512.Create(Unsafe.Add(ref stateRef, 8)).AsByte();
		o.V512_9 = Vector512.Create(Unsafe.Add(ref stateRef, 9)).AsByte();
		o.V512_10 = Vector512.Create(Unsafe.Add(ref stateRef, 10)).AsByte();
		o.V512_11 = Vector512.Create(Unsafe.Add(ref stateRef, 11)).AsByte();
		// 12
		o.V512_13 = Vector512.Create(Unsafe.Add(ref stateRef, 13)).AsByte();
		o.V512_14 = Vector512.Create(Unsafe.Add(ref stateRef, 14)).AsByte();
		o.V512_15 = Vector512.Create(Unsafe.Add(ref stateRef, 15)).AsByte();

		while (length >= 2048)
		{
			ref readonly VectorBuffer1024 s0 = ref Unsafe.As<byte, VectorBuffer1024>(ref Unsafe.Add(ref sourceRef, offset));
			ref readonly VectorBuffer1024 s1 = ref Unsafe.As<byte, VectorBuffer1024>(ref Unsafe.Add(ref sourceRef, offset + 1024));

			Vector512<byte> t12 = o.V512_12 = (Vector512.Create(counter) + Vector512.CreateSequence<uint>(0, 1)).AsByte();
			VectorBuffer1024 x0 = o;
			o.V512_12 = (Vector512.Create(counter + 16) + Vector512.CreateSequence<uint>(0, 1)).AsByte();
			VectorBuffer1024 x1 = o;

			for (int i = 0; i < rounds; i += 2)
			{
				QuarterRound(ref x0.V512_0, ref x0.V512_4, ref x0.V512_8, ref x0.V512_12);
				QuarterRound(ref x0.V512_1, ref x0.V512_5, ref x0.V512_9, ref x0.V512_13);
				QuarterRound(ref x0.V512_2, ref x0.V512_6, ref x0.V512_10, ref x0.V512_14);
				QuarterRound(ref x0.V512_3, ref x0.V512_7, ref x0.V512_11, ref x0.V512_15);

				QuarterRound(ref x1.V512_0, ref x1.V512_4, ref x1.V512_8, ref x1.V512_12);
				QuarterRound(ref x1.V512_1, ref x1.V512_5, ref x1.V512_9, ref x1.V512_13);
				QuarterRound(ref x1.V512_2, ref x1.V512_6, ref x1.V512_10, ref x1.V512_14);
				QuarterRound(ref x1.V512_3, ref x1.V512_7, ref x1.V512_11, ref x1.V512_15);

				QuarterRound(ref x0.V512_0, ref x0.V512_5, ref x0.V512_10, ref x0.V512_15);
				QuarterRound(ref x0.V512_1, ref x0.V512_6, ref x0.V512_11, ref x0.V512_12);
				QuarterRound(ref x0.V512_2, ref x0.V512_7, ref x0.V512_8, ref x0.V512_13);
				QuarterRound(ref x0.V512_3, ref x0.V512_4, ref x0.V512_9, ref x0.V512_14);

				QuarterRound(ref x1.V512_0, ref x1.V512_5, ref x1.V512_10, ref x1.V512_15);
				QuarterRound(ref x1.V512_1, ref x1.V512_6, ref x1.V512_11, ref x1.V512_12);
				QuarterRound(ref x1.V512_2, ref x1.V512_7, ref x1.V512_8, ref x1.V512_13);
				QuarterRound(ref x1.V512_3, ref x1.V512_4, ref x1.V512_9, ref x1.V512_14);
			}

			x0.V512_0 = (x0.V512_0.AsUInt32() + o.V512_0.AsUInt32()).AsByte();
			x1.V512_0 = (x1.V512_0.AsUInt32() + o.V512_0.AsUInt32()).AsByte();
			x0.V512_1 = (x0.V512_1.AsUInt32() + o.V512_1.AsUInt32()).AsByte();
			x1.V512_1 = (x1.V512_1.AsUInt32() + o.V512_1.AsUInt32()).AsByte();
			x0.V512_2 = (x0.V512_2.AsUInt32() + o.V512_2.AsUInt32()).AsByte();
			x1.V512_2 = (x1.V512_2.AsUInt32() + o.V512_2.AsUInt32()).AsByte();
			x0.V512_3 = (x0.V512_3.AsUInt32() + o.V512_3.AsUInt32()).AsByte();
			x1.V512_3 = (x1.V512_3.AsUInt32() + o.V512_3.AsUInt32()).AsByte();
			x0.V512_4 = (x0.V512_4.AsUInt32() + o.V512_4.AsUInt32()).AsByte();
			x1.V512_4 = (x1.V512_4.AsUInt32() + o.V512_4.AsUInt32()).AsByte();
			x0.V512_5 = (x0.V512_5.AsUInt32() + o.V512_5.AsUInt32()).AsByte();
			x1.V512_5 = (x1.V512_5.AsUInt32() + o.V512_5.AsUInt32()).AsByte();
			x0.V512_6 = (x0.V512_6.AsUInt32() + o.V512_6.AsUInt32()).AsByte();
			x1.V512_6 = (x1.V512_6.AsUInt32() + o.V512_6.AsUInt32()).AsByte();
			x0.V512_7 = (x0.V512_7.AsUInt32() + o.V512_7.AsUInt32()).AsByte();
			x1.V512_7 = (x1.V512_7.AsUInt32() + o.V512_7.AsUInt32()).AsByte();
			x0.V512_8 = (x0.V512_8.AsUInt32() + o.V512_8.AsUInt32()).AsByte();
			x1.V512_8 = (x1.V512_8.AsUInt32() + o.V512_8.AsUInt32()).AsByte();
			x0.V512_9 = (x0.V512_9.AsUInt32() + o.V512_9.AsUInt32()).AsByte();
			x1.V512_9 = (x1.V512_9.AsUInt32() + o.V512_9.AsUInt32()).AsByte();
			x0.V512_10 = (x0.V512_10.AsUInt32() + o.V512_10.AsUInt32()).AsByte();
			x1.V512_10 = (x1.V512_10.AsUInt32() + o.V512_10.AsUInt32()).AsByte();
			x0.V512_11 = (x0.V512_11.AsUInt32() + o.V512_11.AsUInt32()).AsByte();
			x1.V512_11 = (x1.V512_11.AsUInt32() + o.V512_11.AsUInt32()).AsByte();
			x0.V512_12 = (x0.V512_12.AsUInt32() + t12.AsUInt32()).AsByte();
			x1.V512_12 = (x1.V512_12.AsUInt32() + o.V512_12.AsUInt32()).AsByte();
			x0.V512_13 = (x0.V512_13.AsUInt32() + o.V512_13.AsUInt32()).AsByte();
			x1.V512_13 = (x1.V512_13.AsUInt32() + o.V512_13.AsUInt32()).AsByte();
			x0.V512_14 = (x0.V512_14.AsUInt32() + o.V512_14.AsUInt32()).AsByte();
			x1.V512_14 = (x1.V512_14.AsUInt32() + o.V512_14.AsUInt32()).AsByte();
			x0.V512_15 = (x0.V512_15.AsUInt32() + o.V512_15.AsUInt32()).AsByte();
			x1.V512_15 = (x1.V512_15.AsUInt32() + o.V512_15.AsUInt32()).AsByte();

			x0.Transpose();
			x1.Transpose();

			x0.V512_0 ^= s0.V512_0;
			x1.V512_0 ^= s1.V512_0;
			x0.V512_1 ^= s0.V512_1;
			x1.V512_1 ^= s1.V512_1;
			x0.V512_2 ^= s0.V512_2;
			x1.V512_2 ^= s1.V512_2;
			x0.V512_3 ^= s0.V512_3;
			x1.V512_3 ^= s1.V512_3;
			x0.V512_4 ^= s0.V512_4;
			x1.V512_4 ^= s1.V512_4;
			x0.V512_5 ^= s0.V512_5;
			x1.V512_5 ^= s1.V512_5;
			x0.V512_6 ^= s0.V512_6;
			x1.V512_6 ^= s1.V512_6;
			x0.V512_7 ^= s0.V512_7;
			x1.V512_7 ^= s1.V512_7;
			x0.V512_8 ^= s0.V512_8;
			x1.V512_8 ^= s1.V512_8;
			x0.V512_9 ^= s0.V512_9;
			x1.V512_9 ^= s1.V512_9;
			x0.V512_10 ^= s0.V512_10;
			x1.V512_10 ^= s1.V512_10;
			x0.V512_11 ^= s0.V512_11;
			x1.V512_11 ^= s1.V512_11;
			x0.V512_12 ^= s0.V512_12;
			x1.V512_12 ^= s1.V512_12;
			x0.V512_13 ^= s0.V512_13;
			x1.V512_13 ^= s1.V512_13;
			x0.V512_14 ^= s0.V512_14;
			x1.V512_14 ^= s1.V512_14;
			x0.V512_15 ^= s0.V512_15;
			x1.V512_15 ^= s1.V512_15;

			Unsafe.WriteUnaligned(ref Unsafe.Add(ref dstRef, offset), x0);
			Unsafe.WriteUnaligned(ref Unsafe.Add(ref dstRef, offset + 1024), x1);

			counter += 32;
			offset += 2048;
			length -= 2048;
		}

		return offset;
	}
}
