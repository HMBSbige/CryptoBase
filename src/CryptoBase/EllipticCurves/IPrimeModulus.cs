namespace CryptoBase.EllipticCurves;

// An odd prime, which both the Montgomery arithmetic and the curve fields reduce by.
internal interface IPrimeModulus
{
	// The plain value in 64-bit limbs, least significant first.
	static abstract ReadOnlySpan<ulong> Modulus { get; }

	// The length of the big-endian encoding, in bytes.
	static abstract int ByteLength { get; }
}
