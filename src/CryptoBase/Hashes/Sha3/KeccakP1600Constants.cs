namespace CryptoBase.Hashes.Sha3;

// FIPS 202, Sec. 3.2 and 3.3: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf
internal static class KeccakP1600Constants
{
	internal const int Rounds = 24;
	internal const int LaneCount = 25;

	// The ι round constants RC[ir] from Algorithm 6, for round indices 0..23.
	internal static ReadOnlySpan<ulong> RoundConstants =>
	[
		0x0000000000000001UL, 0x0000000000008082UL, 0x800000000000808AUL, 0x8000000080008000UL,
		0x000000000000808BUL, 0x0000000080000001UL, 0x8000000080008081UL, 0x8000000000008009UL,
		0x000000000000008AUL, 0x0000000000000088UL, 0x0000000080008009UL, 0x000000008000000AUL,
		0x000000008000808BUL, 0x800000000000008BUL, 0x8000000000008089UL, 0x8000000000008003UL,
		0x8000000000008002UL, 0x8000000000000080UL, 0x000000000000800AUL, 0x800000008000000AUL,
		0x8000000080008081UL, 0x8000000000008080UL, 0x0000000080000001UL, 0x8000000080008008UL,
	];

	// The ρ offsets from Table 2, indexed by lane x + 5y and reduced modulo the 64-bit lane size.
	internal static ReadOnlySpan<byte> RhoOffsets =>
	[
		0, 1, 62, 28, 27,
		36, 44, 6, 55, 20,
		3, 10, 43, 25, 39,
		41, 45, 15, 21, 8,
		18, 2, 61, 56, 14,
	];
}
