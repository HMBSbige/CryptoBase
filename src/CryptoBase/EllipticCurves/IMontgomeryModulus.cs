namespace CryptoBase.EllipticCurves;

// An odd prime m with R = 2^(64·LimbCount); limbs are least significant first. An implementation must be an inline array of LimbCount ulong values: FieldElement<T> stores its limbs in one.
internal interface IMontgomeryModulus : IPrimeModulus
{
	static abstract int LimbCount { get; }

	static abstract int BitLength { get; }

	static abstract ReadOnlySpan<ulong> MontgomeryOne { get; }

	static abstract ReadOnlySpan<ulong> RSquared { get; }

	// −m⁻¹ mod 2^64.
	static abstract ulong NegativeInverse { get; }

	// Replaces the 2·LimbCount limbs t at product, t < m·R, with a value below 2m that is congruent to t·R⁻¹ modulo m: the upper LimbCount limbs and the returned carry above them. TSelf is the implementing type.
	static virtual ulong Reduce<TSelf>(ref ulong product) where TSelf : struct, IMontgomeryModulus
	{
		return FieldElement<TSelf>.MontgomeryReduce(ref product);
	}

	// Sets the LimbCount limbs at result to x·y·R⁻¹ mod m, for x and y below m. result may be x or y. TSelf is the implementing type.
	static virtual void Multiply<TSelf>(ref ulong x, ref ulong y, ref ulong result) where TSelf : struct, IMontgomeryModulus
	{
		FieldElement<TSelf>.MontgomeryMultiply(ref x, ref y, ref result);
	}

	// As Multiply with y = x, for x below m.
	static virtual void Square<TSelf>(ref ulong x, ref ulong result) where TSelf : struct, IMontgomeryModulus
	{
		FieldElement<TSelf>.MontgomerySquare(ref x, ref result);
	}
}
