namespace CryptoBase.EllipticCurves;

internal readonly struct P256Curve : IEcCurve
{
	public static ReadOnlySpan<ulong> B =>
	[
		0xD89CDF6229C4BDDFUL, 0xACF005CD78843090UL, 0xE5A220ABF7212ED6UL, 0xDC30061D04874834UL,
	];

	public static ReadOnlySpan<ulong> GeneratorX =>
	[
		0x79E730D418A9143CUL, 0x75BA95FC5FEDB601UL, 0x79FB732B77622510UL, 0x18905F76A53755C6UL,
	];

	public static ReadOnlySpan<ulong> GeneratorY =>
	[
		0xDDF25357CE95560AUL, 0x8B4AB8E4BA19E45CUL, 0xD2E88688DD21F325UL, 0x8571FF1825885D85UL,
	];

	public static int GeneratorWindowWidth => 7;
}
