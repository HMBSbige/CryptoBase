namespace CryptoBase.EllipticCurves;

// The curve y² = x³ − 3x + b over the field of p, with a group of prime order n. The constants are elements of that field in Montgomery form, least significant limb first.
internal interface IEcCurve
{
	static abstract ReadOnlySpan<ulong> B { get; }

	static abstract ReadOnlySpan<ulong> GeneratorX { get; }

	static abstract ReadOnlySpan<ulong> GeneratorY { get; }

	static abstract int GeneratorWindowWidth { get; }
}
