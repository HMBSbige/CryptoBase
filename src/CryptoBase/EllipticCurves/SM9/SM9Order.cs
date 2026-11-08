using CryptoBase.Signatures;

namespace CryptoBase.EllipticCurves.SM9;

// N = 36t⁴ + 36t³ + 18t² + 6t + 1 for t = 0x600000000058F98A, the prime order of G1, G2 and GT (GM/T 0044.5 §3.1). Scalars and exponents are elements of FieldElement<SM9Order>.
[InlineArray(4)]
internal struct SM9Order : ISM3NonceOrder
{
	private ulong _limb;

	public static int LimbCount => 4;

	public static int ByteLength => 32;

	public static int BitLength => 256;

	public static ReadOnlySpan<ulong> Modulus =>
	[
		0xE56EE19CD69ECF25UL, 0x49F2934B18EA8BEEUL, 0xD603AB4FF58EC744UL, 0xB640000002A3A6F1UL,
	];

	public static ReadOnlySpan<ulong> MontgomeryOne =>
	[
		0x1A911E63296130DBUL, 0xB60D6CB4E7157411UL, 0x29FC54B00A7138BBUL, 0x49BFFFFFFD5C590EUL,
	];

	public static ReadOnlySpan<ulong> RSquared =>
	[
		0x7598CD79CD750C35UL, 0xE4A08110BB6DAEABUL, 0xBFEE4BAE7D78A1F9UL, 0x8894F5D163695D0EUL,
	];

	public static ulong NegativeInverse => 0x1D02662351974B53UL;

	public static ReadOnlySpan<byte> NonceTag => "SM9 signature nonce"u8;

	public static ReadOnlySpan<ulong> NonceReciprocal =>
	[
		0x74DF4FD4DFC97C31UL, 0x9C95D85EC9C073B0UL, 0x55F73AEBDCD1312CUL, 0x67980E0BEB5759A6UL,
	];
}
