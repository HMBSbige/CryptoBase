using CryptoBase.EllipticCurves;

namespace CryptoBase.Signatures.EdDsa;

// L = 2^446 − 13818066809895115352007386748515426880336692474882178609894547503885, the order of the base point of edwards448.
[InlineArray(7)]
internal struct Ed448Order : IMontgomeryModulus
{
	private ulong _limb;

	public static int LimbCount => 7;

	public static int ByteLength => 56;

	public static int BitLength => 446;

	public static ReadOnlySpan<ulong> Modulus =>
	[
		0x2378C292AB5844F3UL, 0x216CC2728DC58F55UL, 0xC44EDB49AED63690UL, 0xFFFFFFFF7CCA23E9UL,
		0xFFFFFFFFFFFFFFFFUL, 0xFFFFFFFFFFFFFFFFUL, 0x3FFFFFFFFFFFFFFFUL,
	];

	public static ReadOnlySpan<ulong> MontgomeryOne =>
	[
		0x721CF5B5529EEC34UL, 0x7A4CF635C8E9C2ABUL, 0xEEC492D944A725BFUL, 0x000000020CD77058UL,
		0x0000000000000000UL, 0x0000000000000000UL, 0x0000000000000000UL,
	];

	public static ReadOnlySpan<ulong> RSquared =>
	[
		0xE3539257049B9B60UL, 0x7AF32C4BC1B195D9UL, 0x0D66DE2388EA1859UL, 0xAE17CF725EE4D838UL,
		0x1A9CC14BA3C47C44UL, 0x2052BCB7E4D070AFUL, 0x3402A939F823B729UL,
	];

	public static ulong NegativeInverse => 0x03BD440FAE918BC5UL;
}
