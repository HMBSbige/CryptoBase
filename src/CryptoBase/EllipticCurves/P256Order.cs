namespace CryptoBase.EllipticCurves;

[InlineArray(4)]
internal struct P256Order : IMontgomeryModulus
{
	private ulong _limb;

	public static int LimbCount => 4;

	public static int ByteLength => 32;

	public static int BitLength => 256;

	public static ReadOnlySpan<ulong> Modulus =>
	[
		0xF3B9CAC2FC632551UL, 0xBCE6FAADA7179E84UL, 0xFFFFFFFFFFFFFFFFUL, 0xFFFFFFFF00000000UL,
	];

	public static ReadOnlySpan<ulong> MontgomeryOne =>
	[
		0x0C46353D039CDAAFUL, 0x4319055258E8617BUL, 0x0000000000000000UL, 0x00000000FFFFFFFFUL,
	];

	public static ReadOnlySpan<ulong> RSquared =>
	[
		0x83244C95BE79EEA2UL, 0x4699799C49BD6FA6UL, 0x2845B2392B6BEC59UL, 0x66E12D94F3D95620UL,
	];

	public static ulong NegativeInverse => 0xCCD1C8AAEE00BC4FUL;
}
