namespace CryptoBase.EllipticCurves.SM9;

// p = 36t⁴ + 36t³ + 24t² + 6t + 1 for t = 0x600000000058F98A, the characteristic of the SM9 curves (GM/T 0044.5 §3.1), in four 64-bit limbs, for the inversion by SafeGcd.
[InlineArray(4)]
internal struct SM9Modulus : IMontgomeryModulus
{
	private ulong _limb;

	public static int LimbCount => 4;

	public static int ByteLength => 32;

	public static int BitLength => 256;

	public static ReadOnlySpan<ulong> Modulus =>
	[
		0xE56F9B27E351457DUL, 0x21F2934B1A7AEEDBUL, 0xD603AB4FF58EC745UL, 0xB640000002A3A6F1UL,
	];

	public static ReadOnlySpan<ulong> MontgomeryOne =>
	[
		0x1A9064D81CAEBA83UL, 0xDE0D6CB4E5851124UL, 0x29FC54B00A7138BAUL, 0x49BFFFFFFD5C590EUL,
	];

	public static ReadOnlySpan<ulong> RSquared =>
	[
		0x27DEA312B417E2D2UL, 0x88F8105FAE1A5D3FUL, 0xE479B522D6706E7BUL, 0x2EA795A656F62FBDUL,
	];

	public static ulong NegativeInverse => 0x892BC42C2F2EE42BUL;
}
