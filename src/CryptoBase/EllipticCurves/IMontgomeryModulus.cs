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
}
