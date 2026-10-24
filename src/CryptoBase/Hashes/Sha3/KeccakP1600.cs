namespace CryptoBase.Hashes.Sha3;

// Keccak-p[1600, 24], also known as Keccak-f[1600], from FIPS 202, Sec. 3.3 and 3.4: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf
// Lane A[x, y] is at index x + 5y, so on little-endian platforms the state bytes are the FIPS 202 state string S.
internal static partial class KeccakP1600
{
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static void Permute(ref InlineArray25<ulong> state)
	{
		if (IsAvx512Supported)
		{
			PermuteAvx512(ref state);
			return;
		}

		PermuteScalar(ref state);
	}

	[SkipLocalsInit]
	[MethodImpl(MethodImplOptions.NoInlining)]
	internal static void PermuteScalar(ref InlineArray25<ulong> state)
	{
		InlineArray25<ulong> a = state;
		Unsafe.SkipInit(out InlineArray25<ulong> e);

		ulong c0 = a[0] ^ a[5] ^ a[10] ^ a[15] ^ a[20];
		ulong c1 = a[1] ^ a[6] ^ a[11] ^ a[16] ^ a[21];
		ulong c2 = a[2] ^ a[7] ^ a[12] ^ a[17] ^ a[22];
		ulong c3 = a[3] ^ a[8] ^ a[13] ^ a[18] ^ a[23];
		ulong c4 = a[4] ^ a[9] ^ a[14] ^ a[19] ^ a[24];
		ref ulong roundConstants = ref MemoryMarshal.GetReference(KeccakP1600Constants.RoundConstants);

		for (int round = 0; round < KeccakP1600Constants.Rounds; round += 2)
		{
			Round(ref a, ref e, ref c0, ref c1, ref c2, ref c3, ref c4, Unsafe.Add(ref roundConstants, round));
			Round(ref e, ref a, ref c0, ref c1, ref c2, ref c3, ref c4, Unsafe.Add(ref roundConstants, round + 1));
		}

		state = a;
	}

	// Computes the round plane by plane: each output plane reads its five π source lanes, applies θ and ρ, then χ and ι, and folds the result into the column parities c0..c4 for the next round's θ.
	// The constant ρ lookups fold into rotate immediates.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void Round(ref InlineArray25<ulong> a, ref InlineArray25<ulong> e, ref ulong c0, ref ulong c1, ref ulong c2, ref ulong c3, ref ulong c4, ulong roundConstant)
	{
		ReadOnlySpan<byte> rho = KeccakP1600Constants.RhoOffsets;

		ulong d0 = c4 ^ BitOperations.RotateLeft(c1, 1);
		ulong d1 = c0 ^ BitOperations.RotateLeft(c2, 1);
		ulong d2 = c1 ^ BitOperations.RotateLeft(c3, 1);
		ulong d3 = c2 ^ BitOperations.RotateLeft(c4, 1);
		ulong d4 = c3 ^ BitOperations.RotateLeft(c0, 1);

		ulong b0 = a[0] ^ d0;
		ulong b1 = BitOperations.RotateLeft(a[6] ^ d1, rho[6]);
		ulong b2 = BitOperations.RotateLeft(a[12] ^ d2, rho[12]);
		ulong b3 = BitOperations.RotateLeft(a[18] ^ d3, rho[18]);
		ulong b4 = BitOperations.RotateLeft(a[24] ^ d4, rho[24]);
		e[0] = b0 ^ ~b1 & b2 ^ roundConstant;
		c0 = e[0];
		e[1] = b1 ^ ~b2 & b3;
		c1 = e[1];
		e[2] = b2 ^ ~b3 & b4;
		c2 = e[2];
		e[3] = b3 ^ ~b4 & b0;
		c3 = e[3];
		e[4] = b4 ^ ~b0 & b1;
		c4 = e[4];

		b0 = BitOperations.RotateLeft(a[3] ^ d3, rho[3]);
		b1 = BitOperations.RotateLeft(a[9] ^ d4, rho[9]);
		b2 = BitOperations.RotateLeft(a[10] ^ d0, rho[10]);
		b3 = BitOperations.RotateLeft(a[16] ^ d1, rho[16]);
		b4 = BitOperations.RotateLeft(a[22] ^ d2, rho[22]);
		e[5] = b0 ^ ~b1 & b2;
		c0 ^= e[5];
		e[6] = b1 ^ ~b2 & b3;
		c1 ^= e[6];
		e[7] = b2 ^ ~b3 & b4;
		c2 ^= e[7];
		e[8] = b3 ^ ~b4 & b0;
		c3 ^= e[8];
		e[9] = b4 ^ ~b0 & b1;
		c4 ^= e[9];

		b0 = BitOperations.RotateLeft(a[1] ^ d1, rho[1]);
		b1 = BitOperations.RotateLeft(a[7] ^ d2, rho[7]);
		b2 = BitOperations.RotateLeft(a[13] ^ d3, rho[13]);
		b3 = BitOperations.RotateLeft(a[19] ^ d4, rho[19]);
		b4 = BitOperations.RotateLeft(a[20] ^ d0, rho[20]);
		e[10] = b0 ^ ~b1 & b2;
		c0 ^= e[10];
		e[11] = b1 ^ ~b2 & b3;
		c1 ^= e[11];
		e[12] = b2 ^ ~b3 & b4;
		c2 ^= e[12];
		e[13] = b3 ^ ~b4 & b0;
		c3 ^= e[13];
		e[14] = b4 ^ ~b0 & b1;
		c4 ^= e[14];

		b0 = BitOperations.RotateLeft(a[4] ^ d4, rho[4]);
		b1 = BitOperations.RotateLeft(a[5] ^ d0, rho[5]);
		b2 = BitOperations.RotateLeft(a[11] ^ d1, rho[11]);
		b3 = BitOperations.RotateLeft(a[17] ^ d2, rho[17]);
		b4 = BitOperations.RotateLeft(a[23] ^ d3, rho[23]);
		e[15] = b0 ^ ~b1 & b2;
		c0 ^= e[15];
		e[16] = b1 ^ ~b2 & b3;
		c1 ^= e[16];
		e[17] = b2 ^ ~b3 & b4;
		c2 ^= e[17];
		e[18] = b3 ^ ~b4 & b0;
		c3 ^= e[18];
		e[19] = b4 ^ ~b0 & b1;
		c4 ^= e[19];

		b0 = BitOperations.RotateLeft(a[2] ^ d2, rho[2]);
		b1 = BitOperations.RotateLeft(a[8] ^ d3, rho[8]);
		b2 = BitOperations.RotateLeft(a[14] ^ d4, rho[14]);
		b3 = BitOperations.RotateLeft(a[15] ^ d0, rho[15]);
		b4 = BitOperations.RotateLeft(a[21] ^ d1, rho[21]);
		e[20] = b0 ^ ~b1 & b2;
		c0 ^= e[20];
		e[21] = b1 ^ ~b2 & b3;
		c1 ^= e[21];
		e[22] = b2 ^ ~b3 & b4;
		c2 ^= e[22];
		e[23] = b3 ^ ~b4 & b0;
		c3 ^= e[23];
		e[24] = b4 ^ ~b0 & b1;
		c4 ^= e[24];
	}
}
