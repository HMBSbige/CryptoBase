namespace CryptoBase.SymmetricCryptos.StreamCryptos;

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

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static int SalsaCoreSoA1024Avx512(byte rounds, Span<uint> state, ReadOnlySpan<byte> source, Span<byte> destination)
	{
		int offset = 0;
		int length = source.Length;

		ref uint stateRef = ref state.GetReference();
		ref byte sourceRef = ref source.GetReference();
		ref byte dstRef = ref destination.GetReference();

		ref ulong counter = ref GetCounter(ref stateRef);

		Unsafe.SkipInit(out Vector512X16<uint> o);
		o.V0 = Vector512.Create(Unsafe.Add(ref stateRef, 0));
		o.V1 = Vector512.Create(Unsafe.Add(ref stateRef, 1));
		o.V2 = Vector512.Create(Unsafe.Add(ref stateRef, 2));
		o.V3 = Vector512.Create(Unsafe.Add(ref stateRef, 3));
		o.V4 = Vector512.Create(Unsafe.Add(ref stateRef, 4));
		o.V5 = Vector512.Create(Unsafe.Add(ref stateRef, 5));
		o.V6 = Vector512.Create(Unsafe.Add(ref stateRef, 6));
		o.V7 = Vector512.Create(Unsafe.Add(ref stateRef, 7));
		// 8
		// 9
		o.V10 = Vector512.Create(Unsafe.Add(ref stateRef, 10));
		o.V11 = Vector512.Create(Unsafe.Add(ref stateRef, 11));
		o.V12 = Vector512.Create(Unsafe.Add(ref stateRef, 12));
		o.V13 = Vector512.Create(Unsafe.Add(ref stateRef, 13));
		o.V14 = Vector512.Create(Unsafe.Add(ref stateRef, 14));
		o.V15 = Vector512.Create(Unsafe.Add(ref stateRef, 15));

		while (length >= 1024)
		{
			ref readonly Vector512X16<byte> s = ref Unsafe.As<byte, Vector512X16<byte>>(ref Unsafe.Add(ref sourceRef, offset));

			ChaCha20Utils.AddAndTranspose(counter, out o.V8, out o.V9);
			Vector512X16<uint> x = o;

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

			counter += 16;
			offset += 1024;
			length -= 1024;
		}

		return offset;
	}

	public static int SalsaCoreSoA2048Avx512(byte rounds, Span<uint> state, ReadOnlySpan<byte> source, Span<byte> destination)
	{
		int offset = 0;
		int length = source.Length;

		ref uint stateRef = ref state.GetReference();
		ref byte sourceRef = ref source.GetReference();
		ref byte dstRef = ref destination.GetReference();

		ref ulong counter = ref GetCounter(ref stateRef);

		Unsafe.SkipInit(out Vector512X16<uint> o);
		o.V0 = Vector512.Create(Unsafe.Add(ref stateRef, 0));
		o.V1 = Vector512.Create(Unsafe.Add(ref stateRef, 1));
		o.V2 = Vector512.Create(Unsafe.Add(ref stateRef, 2));
		o.V3 = Vector512.Create(Unsafe.Add(ref stateRef, 3));
		o.V4 = Vector512.Create(Unsafe.Add(ref stateRef, 4));
		o.V5 = Vector512.Create(Unsafe.Add(ref stateRef, 5));
		o.V6 = Vector512.Create(Unsafe.Add(ref stateRef, 6));
		o.V7 = Vector512.Create(Unsafe.Add(ref stateRef, 7));
		// 8
		// 9
		o.V10 = Vector512.Create(Unsafe.Add(ref stateRef, 10));
		o.V11 = Vector512.Create(Unsafe.Add(ref stateRef, 11));
		o.V12 = Vector512.Create(Unsafe.Add(ref stateRef, 12));
		o.V13 = Vector512.Create(Unsafe.Add(ref stateRef, 13));
		o.V14 = Vector512.Create(Unsafe.Add(ref stateRef, 14));
		o.V15 = Vector512.Create(Unsafe.Add(ref stateRef, 15));

		while (length >= 2048)
		{
			ref readonly Vector512X16<byte> s0 = ref Unsafe.As<byte, Vector512X16<byte>>(ref Unsafe.Add(ref sourceRef, offset));
			ref readonly Vector512X16<byte> s1 = ref Unsafe.As<byte, Vector512X16<byte>>(ref Unsafe.Add(ref sourceRef, offset + 1024));

			ChaCha20Utils.AddAndTranspose(counter, out o.V8, out o.V9);
			Vector512<uint> t8 = o.V8;
			Vector512<uint> t9 = o.V9;
			Vector512X16<uint> x0 = o;

			ChaCha20Utils.AddAndTranspose(counter + 16, out o.V8, out o.V9);
			Vector512X16<uint> x1 = o;

			for (int i = 0; i < rounds; i += 2)
			{
				QuarterRound(ref x0.V4, ref x0.V0, ref x0.V12, ref x0.V8);
				QuarterRound(ref x0.V9, ref x0.V5, ref x0.V1, ref x0.V13);
				QuarterRound(ref x0.V14, ref x0.V10, ref x0.V6, ref x0.V2);
				QuarterRound(ref x0.V3, ref x0.V15, ref x0.V11, ref x0.V7);

				QuarterRound(ref x1.V4, ref x1.V0, ref x1.V12, ref x1.V8);
				QuarterRound(ref x1.V9, ref x1.V5, ref x1.V1, ref x1.V13);
				QuarterRound(ref x1.V14, ref x1.V10, ref x1.V6, ref x1.V2);
				QuarterRound(ref x1.V3, ref x1.V15, ref x1.V11, ref x1.V7);

				QuarterRound(ref x0.V1, ref x0.V0, ref x0.V3, ref x0.V2);
				QuarterRound(ref x0.V6, ref x0.V5, ref x0.V4, ref x0.V7);
				QuarterRound(ref x0.V11, ref x0.V10, ref x0.V9, ref x0.V8);
				QuarterRound(ref x0.V12, ref x0.V15, ref x0.V14, ref x0.V13);

				QuarterRound(ref x1.V1, ref x1.V0, ref x1.V3, ref x1.V2);
				QuarterRound(ref x1.V6, ref x1.V5, ref x1.V4, ref x1.V7);
				QuarterRound(ref x1.V11, ref x1.V10, ref x1.V9, ref x1.V8);
				QuarterRound(ref x1.V12, ref x1.V15, ref x1.V14, ref x1.V13);
			}

			x0.V0 += o.V0;
			x0.V1 += o.V1;
			x0.V2 += o.V2;
			x0.V3 += o.V3;
			x0.V4 += o.V4;
			x0.V5 += o.V5;
			x0.V6 += o.V6;
			x0.V7 += o.V7;
			x0.V8 += t8;
			x0.V9 += t9;
			x0.V10 += o.V10;
			x0.V11 += o.V11;
			x0.V12 += o.V12;
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
