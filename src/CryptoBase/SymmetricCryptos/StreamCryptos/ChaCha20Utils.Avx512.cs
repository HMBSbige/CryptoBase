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

	public static int ChaChaCoreSoA1024Avx512(byte rounds, Span<uint> state, ReadOnlySpan<byte> source, Span<byte> destination)
	{
		int offset = 0;
		int length = source.Length;

		ref uint stateRef = ref state.GetReference();
		ref byte sourceRef = ref source.GetReference();
		ref byte dstRef = ref destination.GetReference();

		ref uint counter = ref Unsafe.Add(ref stateRef, 12);

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
}
