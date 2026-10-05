namespace CryptoBase.Ciphers.Streams;

internal static partial class Salsa20Utils
{
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static ref ulong GetCounter(ref uint state)
	{
		return ref Unsafe.As<uint, ulong>(ref Unsafe.Add(ref state, 8));
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static void UpdateKeyStream(in int rounds, in ReadOnlySpan<uint> state, in Span<byte> keyStream)
	{
		Debug.Assert(state.Length is 16 && keyStream.Length is 64);

		ref uint stateRef = ref state.GetReference();
		uint x00 = Unsafe.Add(ref stateRef, 0), x01 = Unsafe.Add(ref stateRef, 1), x02 = Unsafe.Add(ref stateRef, 2), x03 = Unsafe.Add(ref stateRef, 3);
		uint x04 = Unsafe.Add(ref stateRef, 4), x05 = Unsafe.Add(ref stateRef, 5), x06 = Unsafe.Add(ref stateRef, 6), x07 = Unsafe.Add(ref stateRef, 7);
		uint x08 = Unsafe.Add(ref stateRef, 8), x09 = Unsafe.Add(ref stateRef, 9), x10 = Unsafe.Add(ref stateRef, 10), x11 = Unsafe.Add(ref stateRef, 11);
		uint x12 = Unsafe.Add(ref stateRef, 12), x13 = Unsafe.Add(ref stateRef, 13), x14 = Unsafe.Add(ref stateRef, 14), x15 = Unsafe.Add(ref stateRef, 15);
		PermuteScalar(rounds, ref x00, ref x01, ref x02, ref x03, ref x04, ref x05, ref x06, ref x07, ref x08, ref x09, ref x10, ref x11, ref x12, ref x13, ref x14, ref x15);

		ref byte destination = ref keyStream.GetReference();
		SnuffleCipher.WriteKeyStreamRow(ref destination, x00 + Unsafe.Add(ref stateRef, 0), x01 + Unsafe.Add(ref stateRef, 1), x02 + Unsafe.Add(ref stateRef, 2), x03 + Unsafe.Add(ref stateRef, 3));
		SnuffleCipher.WriteKeyStreamRow(ref Unsafe.Add(ref destination, 16), x04 + Unsafe.Add(ref stateRef, 4), x05 + Unsafe.Add(ref stateRef, 5), x06 + Unsafe.Add(ref stateRef, 6), x07 + Unsafe.Add(ref stateRef, 7));
		SnuffleCipher.WriteKeyStreamRow(ref Unsafe.Add(ref destination, 32), x08 + Unsafe.Add(ref stateRef, 8), x09 + Unsafe.Add(ref stateRef, 9), x10 + Unsafe.Add(ref stateRef, 10), x11 + Unsafe.Add(ref stateRef, 11));
		SnuffleCipher.WriteKeyStreamRow(ref Unsafe.Add(ref destination, 48), x12 + Unsafe.Add(ref stateRef, 12), x13 + Unsafe.Add(ref stateRef, 13), x14 + Unsafe.Add(ref stateRef, 14), x15 + Unsafe.Add(ref stateRef, 15));
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static void SalsaRound(in int rounds, in Span<uint> x)
	{
		uint x15 = x[15], x14 = x[14], x13 = x[13], x12 = x[12];
		uint x11 = x[11], x10 = x[10], x09 = x[9], x08 = x[8];
		uint x07 = x[7], x06 = x[6], x05 = x[5], x04 = x[4];
		uint x03 = x[3], x02 = x[2], x01 = x[1], x00 = x[0];

		PermuteScalar(rounds, ref x00, ref x01, ref x02, ref x03, ref x04, ref x05, ref x06, ref x07, ref x08, ref x09, ref x10, ref x11, ref x12, ref x13, ref x14, ref x15);

		x[15] = x15;
		x[14] = x14;
		x[13] = x13;
		x[12] = x12;
		x[11] = x11;
		x[10] = x10;
		x[9] = x09;
		x[8] = x08;
		x[7] = x07;
		x[6] = x06;
		x[5] = x05;
		x[4] = x04;
		x[3] = x03;
		x[2] = x02;
		x[1] = x01;
		x[0] = x00;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void QuarterRound(ref uint a, ref uint b, ref uint c, ref uint d)
	{
		a ^= (b + c).RotateLeft(7);
		d ^= (a + b).RotateLeft(9);
		c ^= (d + a).RotateLeft(13);
		b ^= (c + d).RotateLeft(18);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void PermuteScalar(int rounds, ref uint x00, ref uint x01, ref uint x02, ref uint x03, ref uint x04, ref uint x05, ref uint x06, ref uint x07, ref uint x08, ref uint x09, ref uint x10, ref uint x11, ref uint x12, ref uint x13, ref uint x14, ref uint x15)
	{
		for (int i = 0; i < rounds; i += 2)
		{
			QuarterRound(ref x04, ref x00, ref x12, ref x08);
			QuarterRound(ref x09, ref x05, ref x01, ref x13);
			QuarterRound(ref x14, ref x10, ref x06, ref x02);
			QuarterRound(ref x03, ref x15, ref x11, ref x07);

			QuarterRound(ref x01, ref x00, ref x03, ref x02);
			QuarterRound(ref x06, ref x05, ref x04, ref x07);
			QuarterRound(ref x11, ref x10, ref x09, ref x08);
			QuarterRound(ref x12, ref x15, ref x14, ref x13);
		}
	}
}
