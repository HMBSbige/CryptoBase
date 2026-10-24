namespace CryptoBase.EllipticCurves;

// An odd prime m with R = 2^(64·LimbCount); limbs are least significant first. An implementation must be an inline array of LimbCount ulong values: FieldElement<T> stores its limbs in one.
internal interface IMontgomeryModulus
{
	static abstract int LimbCount { get; }

	// ⌈BitLength / 8⌉, the length of the big-endian encoding.
	static abstract int ByteLength { get; }

	static abstract int BitLength { get; }

	static abstract ReadOnlySpan<ulong> Modulus { get; }

	static abstract ReadOnlySpan<ulong> MontgomeryOne { get; }

	static abstract ReadOnlySpan<ulong> RSquared { get; }

	// −m⁻¹ mod 2^64.
	static abstract ulong NegativeInverse { get; }

	// The addition chain along which Invert raises an element x to m − 2. The first byte is a count k, and each following pair of bytes (s, j) is a step that squares the power s times and then multiplies it by entry j of a table. The power starts at x, and so does the table, which gains the result of each of the first k steps.
	static abstract ReadOnlySpan<byte> InversionChain { get; }

	// Replaces the 2·LimbCount limbs t at product, t < m·R, with a value below 2m that is congruent to t·R⁻¹ modulo m: the upper LimbCount limbs and the returned carry above them. TSelf is the implementing type.
	static virtual ulong Reduce<TSelf>(ref ulong product) where TSelf : struct, IMontgomeryModulus
	{
		return FieldElement<TSelf>.MontgomeryReduce(ref product);
	}
}
