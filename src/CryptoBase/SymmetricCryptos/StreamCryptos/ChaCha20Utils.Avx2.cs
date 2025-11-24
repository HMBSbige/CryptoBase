namespace CryptoBase.SymmetricCryptos.StreamCryptos;

internal static partial class ChaCha20Utils
{
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void QuarterRound(ref Vector256<byte> a, ref Vector256<byte> b, ref Vector256<byte> c, ref Vector256<byte> d)
	{
		a = (a.AsUInt32() + b.AsUInt32()).AsByte();
		d = (a ^ d).RotateLeftUInt32_16();

		c = (c.AsUInt32() + d.AsUInt32()).AsByte();
		b = (b ^ c).RotateLeftUInt32(12);

		a = (a.AsUInt32() + b.AsUInt32()).AsByte();
		d = (a ^ d).RotateLeftUInt32_8();

		c = (c.AsUInt32() + d.AsUInt32()).AsByte();
		b = (b ^ c).RotateLeftUInt32(7);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static void AddAndTranspose(in ulong counter, out Vector256<byte> outCounterLow, out Vector256<byte> outCounterHigh)
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
		outCounterLow = Avx2.PermuteVar8x32(b0, control).AsByte();
		outCounterHigh = Avx2.PermuteVar8x32(b1, control).AsByte();
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

		Unsafe.SkipInit(out VectorBuffer512 o);
		o.V256_0 = Vector256.Create(Unsafe.Add(ref stateRef, 0)).AsByte();
		o.V256_1 = Vector256.Create(Unsafe.Add(ref stateRef, 1)).AsByte();
		o.V256_2 = Vector256.Create(Unsafe.Add(ref stateRef, 2)).AsByte();
		o.V256_3 = Vector256.Create(Unsafe.Add(ref stateRef, 3)).AsByte();
		o.V256_4 = Vector256.Create(Unsafe.Add(ref stateRef, 4)).AsByte();
		o.V256_5 = Vector256.Create(Unsafe.Add(ref stateRef, 5)).AsByte();
		o.V256_6 = Vector256.Create(Unsafe.Add(ref stateRef, 6)).AsByte();
		o.V256_7 = Vector256.Create(Unsafe.Add(ref stateRef, 7)).AsByte();
		o.V256_8 = Vector256.Create(Unsafe.Add(ref stateRef, 8)).AsByte();
		o.V256_9 = Vector256.Create(Unsafe.Add(ref stateRef, 9)).AsByte();
		o.V256_10 = Vector256.Create(Unsafe.Add(ref stateRef, 10)).AsByte();
		o.V256_11 = Vector256.Create(Unsafe.Add(ref stateRef, 11)).AsByte();
		// 12
		// 13
		o.V256_14 = Vector256.Create(Unsafe.Add(ref stateRef, 14)).AsByte();
		o.V256_15 = Vector256.Create(Unsafe.Add(ref stateRef, 15)).AsByte();

		while (length >= 512)
		{
			ref readonly VectorBuffer512 s = ref Unsafe.As<byte, VectorBuffer512>(ref Unsafe.Add(ref sourceRef, offset));

			AddAndTranspose(counter, out o.V256_12, out o.V256_13);

			VectorBuffer512 x = o;

			for (int i = 0; i < rounds; i += 2)
			{
				QuarterRound(ref x.V256_0, ref x.V256_4, ref x.V256_8, ref x.V256_12);
				QuarterRound(ref x.V256_1, ref x.V256_5, ref x.V256_9, ref x.V256_13);
				QuarterRound(ref x.V256_2, ref x.V256_6, ref x.V256_10, ref x.V256_14);
				QuarterRound(ref x.V256_3, ref x.V256_7, ref x.V256_11, ref x.V256_15);
				QuarterRound(ref x.V256_0, ref x.V256_5, ref x.V256_10, ref x.V256_15);
				QuarterRound(ref x.V256_1, ref x.V256_6, ref x.V256_11, ref x.V256_12);
				QuarterRound(ref x.V256_2, ref x.V256_7, ref x.V256_8, ref x.V256_13);
				QuarterRound(ref x.V256_3, ref x.V256_4, ref x.V256_9, ref x.V256_14);
			}

			x.V256_0 = (x.V256_0.AsUInt32() + o.V256_0.AsUInt32()).AsByte();
			x.V256_1 = (x.V256_1.AsUInt32() + o.V256_1.AsUInt32()).AsByte();
			x.V256_2 = (x.V256_2.AsUInt32() + o.V256_2.AsUInt32()).AsByte();
			x.V256_3 = (x.V256_3.AsUInt32() + o.V256_3.AsUInt32()).AsByte();
			x.V256_4 = (x.V256_4.AsUInt32() + o.V256_4.AsUInt32()).AsByte();
			x.V256_5 = (x.V256_5.AsUInt32() + o.V256_5.AsUInt32()).AsByte();
			x.V256_6 = (x.V256_6.AsUInt32() + o.V256_6.AsUInt32()).AsByte();
			x.V256_7 = (x.V256_7.AsUInt32() + o.V256_7.AsUInt32()).AsByte();
			x.V256_8 = (x.V256_8.AsUInt32() + o.V256_8.AsUInt32()).AsByte();
			x.V256_9 = (x.V256_9.AsUInt32() + o.V256_9.AsUInt32()).AsByte();
			x.V256_10 = (x.V256_10.AsUInt32() + o.V256_10.AsUInt32()).AsByte();
			x.V256_11 = (x.V256_11.AsUInt32() + o.V256_11.AsUInt32()).AsByte();
			x.V256_12 = (x.V256_12.AsUInt32() + o.V256_12.AsUInt32()).AsByte();
			x.V256_13 = (x.V256_13.AsUInt32() + o.V256_13.AsUInt32()).AsByte();
			x.V256_14 = (x.V256_14.AsUInt32() + o.V256_14.AsUInt32()).AsByte();
			x.V256_15 = (x.V256_15.AsUInt32() + o.V256_15.AsUInt32()).AsByte();

			x.Transpose();

			x.V256_0 ^= s.V256_0;
			x.V256_1 ^= s.V256_1;
			x.V256_2 ^= s.V256_2;
			x.V256_3 ^= s.V256_3;
			x.V256_4 ^= s.V256_4;
			x.V256_5 ^= s.V256_5;
			x.V256_6 ^= s.V256_6;
			x.V256_7 ^= s.V256_7;
			x.V256_8 ^= s.V256_8;
			x.V256_9 ^= s.V256_9;
			x.V256_10 ^= s.V256_10;
			x.V256_11 ^= s.V256_11;
			x.V256_12 ^= s.V256_12;
			x.V256_13 ^= s.V256_13;
			x.V256_14 ^= s.V256_14;
			x.V256_15 ^= s.V256_15;

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

		Unsafe.SkipInit(out VectorBuffer512 o);
		o.V256_0 = Vector256.Create(Unsafe.Add(ref stateRef, 0)).AsByte();
		o.V256_1 = Vector256.Create(Unsafe.Add(ref stateRef, 1)).AsByte();
		o.V256_2 = Vector256.Create(Unsafe.Add(ref stateRef, 2)).AsByte();
		o.V256_3 = Vector256.Create(Unsafe.Add(ref stateRef, 3)).AsByte();
		o.V256_4 = Vector256.Create(Unsafe.Add(ref stateRef, 4)).AsByte();
		o.V256_5 = Vector256.Create(Unsafe.Add(ref stateRef, 5)).AsByte();
		o.V256_6 = Vector256.Create(Unsafe.Add(ref stateRef, 6)).AsByte();
		o.V256_7 = Vector256.Create(Unsafe.Add(ref stateRef, 7)).AsByte();
		o.V256_8 = Vector256.Create(Unsafe.Add(ref stateRef, 8)).AsByte();
		o.V256_9 = Vector256.Create(Unsafe.Add(ref stateRef, 9)).AsByte();
		o.V256_10 = Vector256.Create(Unsafe.Add(ref stateRef, 10)).AsByte();
		o.V256_11 = Vector256.Create(Unsafe.Add(ref stateRef, 11)).AsByte();
		// 12
		o.V256_13 = Vector256.Create(Unsafe.Add(ref stateRef, 13)).AsByte();
		o.V256_14 = Vector256.Create(Unsafe.Add(ref stateRef, 14)).AsByte();
		o.V256_15 = Vector256.Create(Unsafe.Add(ref stateRef, 15)).AsByte();

		while (length >= 512)
		{
			ref readonly VectorBuffer512 s = ref Unsafe.As<byte, VectorBuffer512>(ref Unsafe.Add(ref sourceRef, offset));

			o.V256_12 = (Vector256.Create(counter) + Vector256.Create(0u, 1, 2, 3, 4, 5, 6, 7)).AsByte();
			VectorBuffer512 x = o;

			for (int i = 0; i < rounds; i += 2)
			{
				QuarterRound(ref x.V256_0, ref x.V256_4, ref x.V256_8, ref x.V256_12);
				QuarterRound(ref x.V256_1, ref x.V256_5, ref x.V256_9, ref x.V256_13);
				QuarterRound(ref x.V256_2, ref x.V256_6, ref x.V256_10, ref x.V256_14);
				QuarterRound(ref x.V256_3, ref x.V256_7, ref x.V256_11, ref x.V256_15);
				QuarterRound(ref x.V256_0, ref x.V256_5, ref x.V256_10, ref x.V256_15);
				QuarterRound(ref x.V256_1, ref x.V256_6, ref x.V256_11, ref x.V256_12);
				QuarterRound(ref x.V256_2, ref x.V256_7, ref x.V256_8, ref x.V256_13);
				QuarterRound(ref x.V256_3, ref x.V256_4, ref x.V256_9, ref x.V256_14);
			}

			x.V256_0 = (x.V256_0.AsUInt32() + o.V256_0.AsUInt32()).AsByte();
			x.V256_1 = (x.V256_1.AsUInt32() + o.V256_1.AsUInt32()).AsByte();
			x.V256_2 = (x.V256_2.AsUInt32() + o.V256_2.AsUInt32()).AsByte();
			x.V256_3 = (x.V256_3.AsUInt32() + o.V256_3.AsUInt32()).AsByte();
			x.V256_4 = (x.V256_4.AsUInt32() + o.V256_4.AsUInt32()).AsByte();
			x.V256_5 = (x.V256_5.AsUInt32() + o.V256_5.AsUInt32()).AsByte();
			x.V256_6 = (x.V256_6.AsUInt32() + o.V256_6.AsUInt32()).AsByte();
			x.V256_7 = (x.V256_7.AsUInt32() + o.V256_7.AsUInt32()).AsByte();
			x.V256_8 = (x.V256_8.AsUInt32() + o.V256_8.AsUInt32()).AsByte();
			x.V256_9 = (x.V256_9.AsUInt32() + o.V256_9.AsUInt32()).AsByte();
			x.V256_10 = (x.V256_10.AsUInt32() + o.V256_10.AsUInt32()).AsByte();
			x.V256_11 = (x.V256_11.AsUInt32() + o.V256_11.AsUInt32()).AsByte();
			x.V256_12 = (x.V256_12.AsUInt32() + o.V256_12.AsUInt32()).AsByte();
			x.V256_13 = (x.V256_13.AsUInt32() + o.V256_13.AsUInt32()).AsByte();
			x.V256_14 = (x.V256_14.AsUInt32() + o.V256_14.AsUInt32()).AsByte();
			x.V256_15 = (x.V256_15.AsUInt32() + o.V256_15.AsUInt32()).AsByte();

			x.Transpose();

			x.V256_0 ^= s.V256_0;
			x.V256_1 ^= s.V256_1;
			x.V256_2 ^= s.V256_2;
			x.V256_3 ^= s.V256_3;
			x.V256_4 ^= s.V256_4;
			x.V256_5 ^= s.V256_5;
			x.V256_6 ^= s.V256_6;
			x.V256_7 ^= s.V256_7;
			x.V256_8 ^= s.V256_8;
			x.V256_9 ^= s.V256_9;
			x.V256_10 ^= s.V256_10;
			x.V256_11 ^= s.V256_11;
			x.V256_12 ^= s.V256_12;
			x.V256_13 ^= s.V256_13;
			x.V256_14 ^= s.V256_14;
			x.V256_15 ^= s.V256_15;

			Unsafe.WriteUnaligned(ref Unsafe.Add(ref dstRef, offset), x);

			counter += 8;
			length -= 512;
			offset += 512;
		}

		return offset;
	}
}
