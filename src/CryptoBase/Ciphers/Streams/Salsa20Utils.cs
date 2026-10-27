namespace CryptoBase.Ciphers.Streams;

internal static partial class Salsa20Utils
{
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static ref ulong GetCounter(ref uint state)
	{
		return ref Unsafe.As<uint, ulong>(ref Unsafe.Add(ref state, 8));
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static void UpdateKeyStream(in ReadOnlySpan<uint> state, in Span<byte> keyStream)
	{
		Debug.Assert(state.Length is 16 && keyStream.Length is 64);

		ref uint stateRef = ref MemoryMarshal.GetReference(state);
		uint x00 = Unsafe.Add(ref stateRef, 0), x01 = Unsafe.Add(ref stateRef, 1), x02 = Unsafe.Add(ref stateRef, 2), x03 = Unsafe.Add(ref stateRef, 3);
		uint x04 = Unsafe.Add(ref stateRef, 4), x05 = Unsafe.Add(ref stateRef, 5), x06 = Unsafe.Add(ref stateRef, 6), x07 = Unsafe.Add(ref stateRef, 7);
		uint x08 = Unsafe.Add(ref stateRef, 8), x09 = Unsafe.Add(ref stateRef, 9), x10 = Unsafe.Add(ref stateRef, 10), x11 = Unsafe.Add(ref stateRef, 11);
		uint x12 = Unsafe.Add(ref stateRef, 12), x13 = Unsafe.Add(ref stateRef, 13), x14 = Unsafe.Add(ref stateRef, 14), x15 = Unsafe.Add(ref stateRef, 15);
		PermuteScalar(ref x00, ref x01, ref x02, ref x03, ref x04, ref x05, ref x06, ref x07, ref x08, ref x09, ref x10, ref x11, ref x12, ref x13, ref x14, ref x15);

		ref byte destination = ref MemoryMarshal.GetReference(keyStream);
		SnuffleCipher.WriteKeyStreamRow(ref destination, x00 + Unsafe.Add(ref stateRef, 0), x01 + Unsafe.Add(ref stateRef, 1), x02 + Unsafe.Add(ref stateRef, 2), x03 + Unsafe.Add(ref stateRef, 3));
		SnuffleCipher.WriteKeyStreamRow(ref Unsafe.Add(ref destination, 16), x04 + Unsafe.Add(ref stateRef, 4), x05 + Unsafe.Add(ref stateRef, 5), x06 + Unsafe.Add(ref stateRef, 6), x07 + Unsafe.Add(ref stateRef, 7));
		SnuffleCipher.WriteKeyStreamRow(ref Unsafe.Add(ref destination, 32), x08 + Unsafe.Add(ref stateRef, 8), x09 + Unsafe.Add(ref stateRef, 9), x10 + Unsafe.Add(ref stateRef, 10), x11 + Unsafe.Add(ref stateRef, 11));
		SnuffleCipher.WriteKeyStreamRow(ref Unsafe.Add(ref destination, 48), x12 + Unsafe.Add(ref stateRef, 12), x13 + Unsafe.Add(ref stateRef, 13), x14 + Unsafe.Add(ref stateRef, 14), x15 + Unsafe.Add(ref stateRef, 15));
	}

	// Reads the 32-byte key and the first 16 nonce bytes; the state holds the constants in words 0, 5, 10 and 15 and receives the subkey in words 1-4 and 11-14.
	[MethodImpl(MethodImplOptions.NoInlining)]
	internal static void DeriveXSalsa20Key(ref uint stateRef, ref byte key, ref byte nonce)
	{
		ref uint keyRef = ref Unsafe.As<byte, uint>(ref key);
		ref uint nonceRef = ref Unsafe.As<byte, uint>(ref nonce);
		uint x00 = Unsafe.Add(ref stateRef, 0), x01 = Unsafe.Add(ref keyRef, 0), x02 = Unsafe.Add(ref keyRef, 1), x03 = Unsafe.Add(ref keyRef, 2);
		uint x04 = Unsafe.Add(ref keyRef, 3), x05 = Unsafe.Add(ref stateRef, 5), x06 = Unsafe.Add(ref nonceRef, 0), x07 = Unsafe.Add(ref nonceRef, 1);
		uint x08 = Unsafe.Add(ref nonceRef, 2), x09 = Unsafe.Add(ref nonceRef, 3), x10 = Unsafe.Add(ref stateRef, 10), x11 = Unsafe.Add(ref keyRef, 4);
		uint x12 = Unsafe.Add(ref keyRef, 5), x13 = Unsafe.Add(ref keyRef, 6), x14 = Unsafe.Add(ref keyRef, 7), x15 = Unsafe.Add(ref stateRef, 15);
		PermuteScalar(ref x00, ref x01, ref x02, ref x03, ref x04, ref x05, ref x06, ref x07, ref x08, ref x09, ref x10, ref x11, ref x12, ref x13, ref x14, ref x15);

		Unsafe.Add(ref stateRef, 1) = x00;
		Unsafe.Add(ref stateRef, 2) = x05;
		Unsafe.Add(ref stateRef, 3) = x10;
		Unsafe.Add(ref stateRef, 4) = x15;
		Unsafe.Add(ref stateRef, 11) = x06;
		Unsafe.Add(ref stateRef, 12) = x07;
		Unsafe.Add(ref stateRef, 13) = x08;
		Unsafe.Add(ref stateRef, 14) = x09;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void QuarterRound(ref uint a, ref uint b, ref uint c, ref uint d)
	{
		a ^= BitOperations.RotateLeft(b + c, 7);
		d ^= BitOperations.RotateLeft(a + b, 9);
		c ^= BitOperations.RotateLeft(d + a, 13);
		b ^= BitOperations.RotateLeft(c + d, 18);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void PermuteScalar
	(
		ref uint x00, ref uint x01, ref uint x02, ref uint x03,
		ref uint x04, ref uint x05, ref uint x06, ref uint x07,
		ref uint x08, ref uint x09, ref uint x10, ref uint x11,
		ref uint x12, ref uint x13, ref uint x14, ref uint x15
	)
	{
		for (int i = 0; i < SnuffleCipher.Rounds; i += 2)
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
