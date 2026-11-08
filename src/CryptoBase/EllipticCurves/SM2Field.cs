namespace CryptoBase.EllipticCurves;

// p = 2^256 − 2^224 − 2^96 + 2^64 − 1, the prime of the SM2 curve.
[InlineArray(4)]
internal struct SM2Field : IMontgomeryModulus
{
	private ulong _limb;

	public static int LimbCount => 4;

	public static int ByteLength => 32;

	public static int BitLength => 256;

	public static ReadOnlySpan<ulong> Modulus =>
	[
		0xFFFFFFFFFFFFFFFFUL, 0xFFFFFFFF00000000UL, 0xFFFFFFFFFFFFFFFFUL, 0xFFFFFFFEFFFFFFFFUL,
	];

	public static ReadOnlySpan<ulong> MontgomeryOne =>
	[
		0x0000000000000001UL, 0x00000000FFFFFFFFUL, 0x0000000000000000UL, 0x0000000100000000UL,
	];

	public static ReadOnlySpan<ulong> RSquared =>
	[
		0x0000000200000003UL, 0x00000002FFFFFFFFUL, 0x0000000100000001UL, 0x0000000400000002UL,
	];

	public static ulong NegativeInverse => 0x0000000000000001UL;
}
