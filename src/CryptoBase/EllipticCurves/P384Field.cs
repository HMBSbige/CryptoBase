namespace CryptoBase.EllipticCurves;

// p = 2^384 - 2^128 - 2^96 + 2^32 - 1.
[InlineArray(6)]
internal struct P384Field : IMontgomeryModulus
{
	private ulong _limb;

	public static int LimbCount => 6;

	public static int ByteLength => 48;

	public static int BitLength => 384;

	public static ReadOnlySpan<ulong> Modulus =>
	[
		0x00000000FFFFFFFFUL, 0xFFFFFFFF00000000UL, 0xFFFFFFFFFFFFFFFEUL, 0xFFFFFFFFFFFFFFFFUL,
		0xFFFFFFFFFFFFFFFFUL, 0xFFFFFFFFFFFFFFFFUL,
	];

	public static ReadOnlySpan<ulong> MontgomeryOne =>
	[
		0xFFFFFFFF00000001UL, 0x00000000FFFFFFFFUL, 0x0000000000000001UL, 0x0000000000000000UL,
		0x0000000000000000UL, 0x0000000000000000UL,
	];

	public static ReadOnlySpan<ulong> RSquared =>
	[
		0xFFFFFFFE00000001UL, 0x0000000200000000UL, 0xFFFFFFFE00000000UL, 0x0000000200000000UL,
		0x0000000000000001UL, 0x0000000000000000UL,
	];

	public static ulong NegativeInverse => 0x0000000100000001UL;
}
