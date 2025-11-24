namespace CryptoBase.SymmetricCryptos.StreamCryptos;

internal static partial class Salsa20Utils
{
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void QuarterRound(ref Vector256<byte> a, ref Vector256<byte> b, ref Vector256<byte> c, ref Vector256<byte> d)
	{
		a ^= (b.AsUInt32() + c.AsUInt32()).RotateLeftUInt32(7).AsByte();
		d ^= (a.AsUInt32() + b.AsUInt32()).RotateLeftUInt32(9).AsByte();
		c ^= (d.AsUInt32() + a.AsUInt32()).RotateLeftUInt32(13).AsByte();
		b ^= (c.AsUInt32() + d.AsUInt32()).RotateLeftUInt32(18).AsByte();
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static int SalsaCore512(byte rounds, Span<uint> state, ReadOnlySpan<byte> source, Span<byte> destination)
	{
		int length = source.Length;
		int offset = 0;

		ref uint stateRef = ref state.GetReference();
		ref byte sourceRef = ref source.GetReference();
		ref byte dstRef = ref destination.GetReference();

		ref ulong counter = ref GetCounter(ref stateRef);

		Unsafe.SkipInit(out VectorBuffer512 o);
		o.V256_0 = Vector256.Create(Unsafe.Add(ref stateRef, 0)).AsByte();
		o.V256_1 = Vector256.Create(Unsafe.Add(ref stateRef, 1)).AsByte();
		o.V256_2 = Vector256.Create(Unsafe.Add(ref stateRef, 2)).AsByte();
		o.V256_3 = Vector256.Create(Unsafe.Add(ref stateRef, 3)).AsByte();
		o.V256_4 = Vector256.Create(Unsafe.Add(ref stateRef, 4)).AsByte();
		o.V256_5 = Vector256.Create(Unsafe.Add(ref stateRef, 5)).AsByte();
		o.V256_6 = Vector256.Create(Unsafe.Add(ref stateRef, 6)).AsByte();
		o.V256_7 = Vector256.Create(Unsafe.Add(ref stateRef, 7)).AsByte();
		// 8
		// 9
		o.V256_10 = Vector256.Create(Unsafe.Add(ref stateRef, 10)).AsByte();
		o.V256_11 = Vector256.Create(Unsafe.Add(ref stateRef, 11)).AsByte();
		o.V256_12 = Vector256.Create(Unsafe.Add(ref stateRef, 12)).AsByte();
		o.V256_13 = Vector256.Create(Unsafe.Add(ref stateRef, 13)).AsByte();
		o.V256_14 = Vector256.Create(Unsafe.Add(ref stateRef, 14)).AsByte();
		o.V256_15 = Vector256.Create(Unsafe.Add(ref stateRef, 15)).AsByte();

		while (length >= 512)
		{
			ref readonly VectorBuffer512 s = ref Unsafe.As<byte, VectorBuffer512>(ref Unsafe.Add(ref sourceRef, offset));

			ChaCha20Utils.AddAndTranspose(counter, out o.V256_8, out o.V256_9);

			VectorBuffer512 x = o;

			for (int i = 0; i < rounds; i += 2)
			{
				QuarterRound(ref x.V256_4, ref x.V256_0, ref x.V256_12, ref x.V256_8);
				QuarterRound(ref x.V256_9, ref x.V256_5, ref x.V256_1, ref x.V256_13);
				QuarterRound(ref x.V256_14, ref x.V256_10, ref x.V256_6, ref x.V256_2);
				QuarterRound(ref x.V256_3, ref x.V256_15, ref x.V256_11, ref x.V256_7);

				QuarterRound(ref x.V256_1, ref x.V256_0, ref x.V256_3, ref x.V256_2);
				QuarterRound(ref x.V256_6, ref x.V256_5, ref x.V256_4, ref x.V256_7);
				QuarterRound(ref x.V256_11, ref x.V256_10, ref x.V256_9, ref x.V256_8);
				QuarterRound(ref x.V256_12, ref x.V256_15, ref x.V256_14, ref x.V256_13);
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
