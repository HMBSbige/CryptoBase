namespace CryptoBase.EllipticCurves;

internal readonly struct P256Curve : IECCurve
{
	public static ReadOnlySpan<ulong> B =>
	[
		0x3BCE3C3E27D2604BUL, 0x651D06B0CC53B0F6UL, 0xB3EBBD55769886BCUL, 0x5AC635D8AA3A93E7UL,
	];

	public static ReadOnlySpan<ulong> GeneratorX =>
	[
		0xF4A13945D898C296UL, 0x77037D812DEB33A0UL, 0xF8BCE6E563A440F2UL, 0x6B17D1F2E12C4247UL,
	];

	public static ReadOnlySpan<ulong> GeneratorY =>
	[
		0xCBB6406837BF51F5UL, 0x2BCE33576B315ECEUL, 0x8EE7EB4A7C0F9E16UL, 0x4FE342E2FE1A7F9BUL,
	];

	public static int GeneratorWindowWidth => 7;
}
