namespace CryptoBase.Signatures.MLDsa;

// A parameter set of FIPS 204, Table 1, as a struct so that MLDsaKey folds its sizes into constants.
internal interface IMLDsaParameters
{
	static abstract int K { get; }

	static abstract int L { get; }

	static abstract int Eta { get; }

	static abstract int Tau { get; }

	// λ, the collision strength of c̃, in bits.
	static abstract int Lambda { get; }

	// log2 γ1.
	static abstract int Gamma1Bits { get; }

	static abstract int Gamma2 { get; }

	static abstract int Omega { get; }

	// The SignatureAlgorithm of pure ML-DSA with an empty context.
	static abstract SignatureAlgorithm Algorithm { get; }

	// The DER AlgorithmIdentifier, with absent parameters (RFC 9881, Sec. 2).
	static abstract ReadOnlySpan<byte> AlgorithmIdentifier { get; }
}
