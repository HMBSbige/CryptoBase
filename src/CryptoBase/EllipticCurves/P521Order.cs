namespace CryptoBase.EllipticCurves;

[InlineArray(9)]
internal struct P521Order : IMontgomeryModulus
{
	private ulong _limb;

	public static int LimbCount => 9;

	public static int ByteLength => 66;

	public static int BitLength => 521;

	public static ReadOnlySpan<ulong> Modulus =>
	[
		0xBB6FB71E91386409UL, 0x3BB5C9B8899C47AEUL, 0x7FCC0148F709A5D0UL, 0x51868783BF2F966BUL,
		0xFFFFFFFFFFFFFFFAUL, 0xFFFFFFFFFFFFFFFFUL, 0xFFFFFFFFFFFFFFFFUL, 0xFFFFFFFFFFFFFFFFUL,
		0x00000000000001FFUL,
	];

	public static ReadOnlySpan<ulong> MontgomeryOne =>
	[
		0xFB80000000000000UL, 0x28A2482470B763CDUL, 0x17E2251B23BB31DCUL, 0xCA4019FF5B847B2DUL,
		0x02D73CBC3E206834UL, 0x0000000000000000UL, 0x0000000000000000UL, 0x0000000000000000UL,
		0x0000000000000000UL,
	];

	public static ReadOnlySpan<ulong> RSquared =>
	[
		0x137CD04DCF15DD04UL, 0xF707BADCE5547EA3UL, 0x12A78D38794573FFUL, 0xD3721EF557F75E06UL,
		0xDD6E23D82E49C7DBUL, 0xCFF3D142B7756E3EUL, 0x5BCC6D61A8E567BCUL, 0x2D8E03D1492D0D45UL,
		0x000000000000003DUL,
	];

	public static ulong NegativeInverse => 0x1D2F5CCD79A995C7UL;

	// With x_k = x^(2^k − 1), the table holds x, x², the odd powers of x up to x^31, x_10, x_20, x_40 and x_80. The power goes on to x_260, then the steps follow the bits of n − 2, each appending zeros and an entry.
	public static ReadOnlySpan<byte> InversionChain =>
	[
		20,
		0, 0, 0, 0, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 5, 16, 10, 17, 20, 18, 40, 19,
		20, 18, 80, 20, 80, 20, 4, 7, 5, 3, 5, 2, 8, 7, 8, 8, 10, 15, 5, 16, 7, 12, 5, 13, 6, 13, 5, 11, 5, 12, 5, 16,
		5, 10, 10, 0, 5, 5, 6, 4, 5, 12, 9, 10, 5, 5, 6, 15, 9, 4, 6, 15, 5, 11, 5, 13, 7, 14, 5, 9, 7, 5, 5, 10,
		5, 9, 7, 8, 6, 12, 6, 12, 6, 14, 6, 16, 6, 14, 5, 9, 5, 15, 7, 9, 5, 4, 9, 13, 10, 4,
	];
}
