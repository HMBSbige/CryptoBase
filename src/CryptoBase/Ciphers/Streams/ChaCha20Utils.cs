namespace CryptoBase.Ciphers.Streams;

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
	internal static void DeriveXChaCha20Key(Span<uint> state, ReadOnlySpan<uint> key, ReadOnlySpan<uint> nonce)
	{
		Debug.Assert(state.Length is 16 && key.Length is 8 && nonce.Length >= 4);

		ref uint stateRef = ref state.GetReference();
		ref uint keyRef = ref key.GetReference();
		ref uint nonceRef = ref nonce.GetReference();
		uint x00 = Unsafe.Add(ref stateRef, 0), x01 = Unsafe.Add(ref stateRef, 1), x02 = Unsafe.Add(ref stateRef, 2), x03 = Unsafe.Add(ref stateRef, 3);
		uint x04 = Unsafe.Add(ref keyRef, 0), x05 = Unsafe.Add(ref keyRef, 1), x06 = Unsafe.Add(ref keyRef, 2), x07 = Unsafe.Add(ref keyRef, 3);
		uint x08 = Unsafe.Add(ref keyRef, 4), x09 = Unsafe.Add(ref keyRef, 5), x10 = Unsafe.Add(ref keyRef, 6), x11 = Unsafe.Add(ref keyRef, 7);
		uint x12 = Unsafe.Add(ref nonceRef, 0), x13 = Unsafe.Add(ref nonceRef, 1), x14 = Unsafe.Add(ref nonceRef, 2), x15 = Unsafe.Add(ref nonceRef, 3);
		PermuteScalar(SnuffleCipher.Rounds, ref x00, ref x01, ref x02, ref x03, ref x04, ref x05, ref x06, ref x07, ref x08, ref x09, ref x10, ref x11, ref x12, ref x13, ref x14, ref x15);

		Unsafe.Add(ref stateRef, 4) = x00;
		Unsafe.Add(ref stateRef, 5) = x01;
		Unsafe.Add(ref stateRef, 6) = x02;
		Unsafe.Add(ref stateRef, 7) = x03;
		Unsafe.Add(ref stateRef, 8) = x12;
		Unsafe.Add(ref stateRef, 9) = x13;
		Unsafe.Add(ref stateRef, 10) = x14;
		Unsafe.Add(ref stateRef, 11) = x15;
	}

	[MethodImpl(MethodImplOptions.NoInlining)]
	public static void DerivePoly1305Key(Span<uint> state, Span<byte> destination)
	{
		Debug.Assert(state.Length is 16 && destination.Length is 32);

		ref uint stateRef = ref state.GetReference();
		uint x00 = Unsafe.Add(ref stateRef, 0), x01 = Unsafe.Add(ref stateRef, 1), x02 = Unsafe.Add(ref stateRef, 2), x03 = Unsafe.Add(ref stateRef, 3);
		uint x04 = Unsafe.Add(ref stateRef, 4), x05 = Unsafe.Add(ref stateRef, 5), x06 = Unsafe.Add(ref stateRef, 6), x07 = Unsafe.Add(ref stateRef, 7);
		uint x08 = Unsafe.Add(ref stateRef, 8), x09 = Unsafe.Add(ref stateRef, 9), x10 = Unsafe.Add(ref stateRef, 10), x11 = Unsafe.Add(ref stateRef, 11);
		uint x12 = Unsafe.Add(ref stateRef, 12), x13 = Unsafe.Add(ref stateRef, 13), x14 = Unsafe.Add(ref stateRef, 14), x15 = Unsafe.Add(ref stateRef, 15);
		PermuteScalar(SnuffleCipher.Rounds, ref x00, ref x01, ref x02, ref x03, ref x04, ref x05, ref x06, ref x07, ref x08, ref x09, ref x10, ref x11, ref x12, ref x13, ref x14, ref x15);

		ref byte destinationRef = ref destination.GetReference();
		Unsafe.WriteUnaligned(ref destinationRef, x00 + Unsafe.Add(ref stateRef, 0));
		Unsafe.WriteUnaligned(ref Unsafe.Add(ref destinationRef, 4), x01 + Unsafe.Add(ref stateRef, 1));
		Unsafe.WriteUnaligned(ref Unsafe.Add(ref destinationRef, 8), x02 + Unsafe.Add(ref stateRef, 2));
		Unsafe.WriteUnaligned(ref Unsafe.Add(ref destinationRef, 12), x03 + Unsafe.Add(ref stateRef, 3));
		Unsafe.WriteUnaligned(ref Unsafe.Add(ref destinationRef, 16), x04 + Unsafe.Add(ref stateRef, 4));
		Unsafe.WriteUnaligned(ref Unsafe.Add(ref destinationRef, 20), x05 + Unsafe.Add(ref stateRef, 5));
		Unsafe.WriteUnaligned(ref Unsafe.Add(ref destinationRef, 24), x06 + Unsafe.Add(ref stateRef, 6));
		Unsafe.WriteUnaligned(ref Unsafe.Add(ref destinationRef, 28), x07 + Unsafe.Add(ref stateRef, 7));
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
	private static void PermuteScalar(int rounds, ref uint x00, ref uint x01, ref uint x02, ref uint x03, ref uint x04, ref uint x05, ref uint x06, ref uint x07, ref uint x08, ref uint x09, ref uint x10, ref uint x11, ref uint x12, ref uint x13, ref uint x14, ref uint x15)
	{
		for (int round = 0; round < rounds; round += 2)
		{
			x00 += x04;
			x01 += x05;
			x02 += x06;
			x03 += x07;
			x12 = (x12 ^ x00).RotateLeft(16);
			x13 = (x13 ^ x01).RotateLeft(16);
			x14 = (x14 ^ x02).RotateLeft(16);
			x15 = (x15 ^ x03).RotateLeft(16);
			x08 += x12;
			x09 += x13;
			x10 += x14;
			x11 += x15;
			x04 = (x04 ^ x08).RotateLeft(12);
			x05 = (x05 ^ x09).RotateLeft(12);
			x06 = (x06 ^ x10).RotateLeft(12);
			x07 = (x07 ^ x11).RotateLeft(12);
			x00 += x04;
			x01 += x05;
			x02 += x06;
			x03 += x07;
			x12 = (x12 ^ x00).RotateLeft(8);
			x13 = (x13 ^ x01).RotateLeft(8);
			x14 = (x14 ^ x02).RotateLeft(8);
			x15 = (x15 ^ x03).RotateLeft(8);
			x08 += x12;
			x09 += x13;
			x10 += x14;
			x11 += x15;
			x04 = (x04 ^ x08).RotateLeft(7);
			x05 = (x05 ^ x09).RotateLeft(7);
			x06 = (x06 ^ x10).RotateLeft(7);
			x07 = (x07 ^ x11).RotateLeft(7);
			x00 += x05;
			x01 += x06;
			x02 += x07;
			x03 += x04;
			x15 = (x15 ^ x00).RotateLeft(16);
			x12 = (x12 ^ x01).RotateLeft(16);
			x13 = (x13 ^ x02).RotateLeft(16);
			x14 = (x14 ^ x03).RotateLeft(16);
			x10 += x15;
			x11 += x12;
			x08 += x13;
			x09 += x14;
			x05 = (x05 ^ x10).RotateLeft(12);
			x06 = (x06 ^ x11).RotateLeft(12);
			x07 = (x07 ^ x08).RotateLeft(12);
			x04 = (x04 ^ x09).RotateLeft(12);
			x00 += x05;
			x01 += x06;
			x02 += x07;
			x03 += x04;
			x15 = (x15 ^ x00).RotateLeft(8);
			x12 = (x12 ^ x01).RotateLeft(8);
			x13 = (x13 ^ x02).RotateLeft(8);
			x14 = (x14 ^ x03).RotateLeft(8);
			x10 += x15;
			x11 += x12;
			x08 += x13;
			x09 += x14;
			x05 = (x05 ^ x10).RotateLeft(7);
			x06 = (x06 ^ x11).RotateLeft(7);
			x07 = (x07 ^ x08).RotateLeft(7);
			x04 = (x04 ^ x09).RotateLeft(7);
		}
	}
}
