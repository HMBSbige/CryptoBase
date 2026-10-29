namespace CryptoBase.EllipticCurves;

// The curve y² = x³ − 3x + b over the field of p, with a group of prime order n. The constants are plain values below p, least significant limb of 64 bits first, so that they hold for any IECField of p.
internal interface IECCurve
{
	static abstract ReadOnlySpan<ulong> B { get; }

	static abstract ReadOnlySpan<ulong> GeneratorX { get; }

	static abstract ReadOnlySpan<ulong> GeneratorY { get; }

	static abstract int GeneratorWindowWidth { get; }
}
