namespace CryptoBase.EllipticCurves;

// Five values of SM2Field29x4Avx2, nine vectors each, and two vectors to align them.
[InlineArray(5 * 9 + 2)]
internal struct SM2QuadScratch5
{
	private Vector256<ulong> _element;
}

// Six values of SM2Field29x4Avx2 and two vectors to align them.
[InlineArray(6 * 9 + 2)]
internal struct SM2QuadScratch6
{
	private Vector256<ulong> _element;
}

// Five values of SM2Field29x8Avx512 and a vector to align them.
[InlineArray(5 * 9 + 1)]
internal struct SM2OctoScratch5
{
	private Vector512<ulong> _element;
}
