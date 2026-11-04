namespace CryptoBase.EllipticCurves.Curve448;

// p = 2^448 − 2^224 − 1 in seven 64-bit limbs, for the inversion by SafeGcd. R = 2^448 ≡ 2^224 + 1 (mod p), and p ≡ −1 (mod 2^64), so −p⁻¹ ≡ 1.
[InlineArray(7)]
internal struct Curve448Modulus : IMontgomeryModulus
{
	private ulong _limb;

	public static int LimbCount => 7;

	public static int ByteLength => 56;

	public static int BitLength => 448;

	public static ReadOnlySpan<ulong> Modulus =>
	[
		0xFFFFFFFFFFFFFFFFUL, 0xFFFFFFFFFFFFFFFFUL, 0xFFFFFFFFFFFFFFFFUL, 0xFFFFFFFEFFFFFFFFUL,
		0xFFFFFFFFFFFFFFFFUL, 0xFFFFFFFFFFFFFFFFUL, 0xFFFFFFFFFFFFFFFFUL,
	];

	public static ReadOnlySpan<ulong> MontgomeryOne => [1, 0, 0, 1UL << 32, 0, 0, 0];

	// (2^224 + 1)² = 2^448 + 2^225 + 1 ≡ 3·2^224 + 2.
	public static ReadOnlySpan<ulong> RSquared => [2, 0, 0, 3UL << 32, 0, 0, 0];

	public static ulong NegativeInverse => 1;

	// The numerator for SafeGcd that gives the plain inverse.
	internal static ReadOnlySpan<ulong> One => [1, 0, 0, 0, 0, 0, 0];
}
