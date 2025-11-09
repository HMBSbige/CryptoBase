namespace CryptoBase.SymmetricCryptos.StreamCryptos;

internal static partial class Salsa20Utils
{
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void QuarterRound(ref Vector256<uint> a, ref Vector256<uint> b, ref Vector256<uint> c, ref Vector256<uint> d)
	{
		a ^= (b + c).RotateLeftUInt32(7);
		d ^= (a + b).RotateLeftUInt32(9);
		c ^= (d + a).RotateLeftUInt32(13);
		b ^= (c + d).RotateLeftUInt32(18);
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

		Unsafe.SkipInit(out Vector256X16<uint> o);
		o.V0 = Vector256.Create(Unsafe.Add(ref stateRef, 0));
		o.V1 = Vector256.Create(Unsafe.Add(ref stateRef, 1));
		o.V2 = Vector256.Create(Unsafe.Add(ref stateRef, 2));
		o.V3 = Vector256.Create(Unsafe.Add(ref stateRef, 3));
		o.V4 = Vector256.Create(Unsafe.Add(ref stateRef, 4));
		o.V5 = Vector256.Create(Unsafe.Add(ref stateRef, 5));
		o.V6 = Vector256.Create(Unsafe.Add(ref stateRef, 6));
		o.V7 = Vector256.Create(Unsafe.Add(ref stateRef, 7));
		// 8
		// 9
		o.V10 = Vector256.Create(Unsafe.Add(ref stateRef, 10));
		o.V11 = Vector256.Create(Unsafe.Add(ref stateRef, 11));
		o.V12 = Vector256.Create(Unsafe.Add(ref stateRef, 12));
		o.V13 = Vector256.Create(Unsafe.Add(ref stateRef, 13));
		o.V14 = Vector256.Create(Unsafe.Add(ref stateRef, 14));
		o.V15 = Vector256.Create(Unsafe.Add(ref stateRef, 15));

		while (length >= 512)
		{
			ref readonly Vector256X16<byte> s = ref Unsafe.As<byte, Vector256X16<byte>>(ref Unsafe.Add(ref sourceRef, offset));

			ChaCha20Utils.AddAndTranspose(counter, out o.V8, out o.V9);

			Vector256X16<uint> x = o;

			for (int i = 0; i < rounds; i += 2)
			{
				QuarterRound(ref x.V4, ref x.V0, ref x.V12, ref x.V8);
				QuarterRound(ref x.V9, ref x.V5, ref x.V1, ref x.V13);
				QuarterRound(ref x.V14, ref x.V10, ref x.V6, ref x.V2);
				QuarterRound(ref x.V3, ref x.V15, ref x.V11, ref x.V7);

				QuarterRound(ref x.V1, ref x.V0, ref x.V3, ref x.V2);
				QuarterRound(ref x.V6, ref x.V5, ref x.V4, ref x.V7);
				QuarterRound(ref x.V11, ref x.V10, ref x.V9, ref x.V8);
				QuarterRound(ref x.V12, ref x.V15, ref x.V14, ref x.V13);
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
