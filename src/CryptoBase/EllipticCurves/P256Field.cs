namespace CryptoBase.EllipticCurves;

// p = 2^256 - 2^224 + 2^192 + 2^96 - 1.
[InlineArray(4)]
internal struct P256Field : IMontgomeryModulus
{
	private ulong _limb;

	public static int LimbCount => 4;

	public static int ByteLength => 32;

	public static int BitLength => 256;

	public static ReadOnlySpan<ulong> Modulus =>
	[
		0xFFFFFFFFFFFFFFFFUL, 0x00000000FFFFFFFFUL, 0x0000000000000000UL, 0xFFFFFFFF00000001UL,
	];

	public static ReadOnlySpan<ulong> MontgomeryOne =>
	[
		0x0000000000000001UL, 0xFFFFFFFF00000000UL, 0xFFFFFFFFFFFFFFFFUL, 0x00000000FFFFFFFEUL,
	];

	public static ReadOnlySpan<ulong> RSquared =>
	[
		0x0000000000000003UL, 0xFFFFFFFBFFFFFFFFUL, 0xFFFFFFFFFFFFFFFEUL, 0x00000004FFFFFFFDUL,
	];

	public static ulong NegativeInverse => 0x0000000000000001UL;
}
