namespace CryptoBase.SymmetricCryptos.StreamCryptos;

internal static partial class ChaCha20Utils
{
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static ref ulong GetCounterOriginal(ref uint state)
	{
		return ref Unsafe.As<uint, ulong>(ref Unsafe.Add(ref state, 12));
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static ref uint GetCounter(ref uint state)
	{
		return ref Unsafe.Add(ref state, 12);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static void UpdateKeyStream(in int rounds, in ReadOnlySpan<uint> state, in Span<byte> keyStream)
	{
		Span<uint> x = MemoryMarshal.Cast<byte, uint>(keyStream);
		state.CopyTo(x);

		ChaChaRound(rounds, x);

		x[15] += state[15];
		x[14] += state[14];
		x[13] += state[13];
		x[12] += state[12];
		x[11] += state[11];
		x[10] += state[10];
		x[9] += state[9];
		x[8] += state[8];
		x[7] += state[7];
		x[6] += state[6];
		x[5] += state[5];
		x[4] += state[4];
		x[3] += state[3];
		x[2] += state[2];
		x[1] += state[1];
		x[0] += state[0];
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static void ChaChaRound(in int rounds, in Span<uint> x)
	{
		uint x15 = x[15], x14 = x[14], x13 = x[13], x12 = x[12];
		uint x11 = x[11], x10 = x[10], x09 = x[9], x08 = x[8];
		uint x07 = x[7], x06 = x[6], x05 = x[5], x04 = x[4];
		uint x03 = x[3], x02 = x[2], x01 = x[1], x00 = x[0];

		for (int i = 0; i < rounds; i += 2)
		{
			QuarterRound(ref x00, ref x04, ref x08, ref x12);
			QuarterRound(ref x01, ref x05, ref x09, ref x13);
			QuarterRound(ref x02, ref x06, ref x10, ref x14);
			QuarterRound(ref x03, ref x07, ref x11, ref x15);

			QuarterRound(ref x00, ref x05, ref x10, ref x15);
			QuarterRound(ref x01, ref x06, ref x11, ref x12);
			QuarterRound(ref x02, ref x07, ref x08, ref x13);
			QuarterRound(ref x03, ref x04, ref x09, ref x14);
		}

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
		Step(ref a, ref b, ref d, 16);
		Step(ref c, ref d, ref b, 12);
		Step(ref a, ref b, ref d, 8);
		Step(ref c, ref d, ref b, 7);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void Step(ref uint a, ref readonly uint b, ref uint c, in int i)
	{
		a += b;
		c = (a ^ c).RotateLeft(i);
	}
}
