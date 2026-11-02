using CryptoBase.EllipticCurves;

namespace CryptoBase.Signatures.EdDsa;

// L = 2^252 + 27742317777372353535851937790883648493, the order of the base point of edwards25519.
[InlineArray(4)]
internal struct Ed25519Order : IMontgomeryModulus
{
	private ulong _limb;

	public static int LimbCount => 4;

	public static int ByteLength => 32;

	public static int BitLength => 253;

	public static ReadOnlySpan<ulong> Modulus =>
	[
		0x5812631A5CF5D3EDUL, 0x14DEF9DEA2F79CD6UL, 0x0000000000000000UL, 0x1000000000000000UL,
	];

	public static ReadOnlySpan<ulong> MontgomeryOne =>
	[
		0xD6EC31748D98951DUL, 0xC6EF5BF4737DCF70UL, 0xFFFFFFFFFFFFFFFEUL, 0x0FFFFFFFFFFFFFFFUL,
	];

	public static ReadOnlySpan<ulong> RSquared =>
	[
		0xA40611E3449C0F01UL, 0xD00E1BA768859347UL, 0xCEEC73D217F5BE65UL, 0x0399411B7C309A3DUL,
	];

	public static ulong NegativeInverse => 0xD2B51DA312547E1BUL;
}
