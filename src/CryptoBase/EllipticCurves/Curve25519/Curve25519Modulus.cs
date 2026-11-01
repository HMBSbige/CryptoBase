namespace CryptoBase.EllipticCurves.Curve25519;

// p = 2^255 − 19 in four 64-bit limbs, for the inversion by SafeGcd.
[InlineArray(4)]
internal struct Curve25519Modulus : IMontgomeryModulus
{
	private ulong _limb;

	public static int LimbCount => 4;

	public static int ByteLength => 32;

	public static int BitLength => 255;

	public static ReadOnlySpan<ulong> Modulus =>
	[
		0xFFFFFFFFFFFFFFEDUL, 0xFFFFFFFFFFFFFFFFUL, 0xFFFFFFFFFFFFFFFFUL, 0x7FFFFFFFFFFFFFFFUL,
	];

	public static ReadOnlySpan<ulong> MontgomeryOne => [38, 0, 0, 0];

	public static ReadOnlySpan<ulong> RSquared => [1444, 0, 0, 0];

	public static ulong NegativeInverse => 0x86BCA1AF286BCA1BUL;

	// The numerator for SafeGcd that gives the plain inverse.
	internal static ReadOnlySpan<ulong> One => [1, 0, 0, 0];
}
