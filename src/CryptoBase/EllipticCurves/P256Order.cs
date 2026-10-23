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

	// With x_k = x^(2^k − 1), the table holds x, x², the odd powers of x up to x^15, x_8, x_16 and x_32. From x_32, the leading 32 ones of
	// n − 2, the steps follow its bits, each appending zeros and an entry.
	public static ReadOnlySpan<byte> InversionChain =>
	[
		11,
		0, 0, 0, 0, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 4, 8, 8, 9, 16, 10,
		33, 0, 32, 11, 32, 11, 5, 8, 5, 4, 6, 7, 4, 8, 4, 3, 5, 6, 5, 7, 5, 4, 4, 0, 5, 8, 4, 2, 4, 7, 5, 0,
		6, 8, 5, 4, 4, 4, 4, 2, 4, 5, 5, 6, 8, 6, 4, 8, 5, 2, 5, 2, 6, 5, 4, 3, 6, 8,
	];
}
