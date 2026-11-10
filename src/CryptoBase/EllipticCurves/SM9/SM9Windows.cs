namespace CryptoBase.EllipticCurves.SM9;

// The digit count of LimbArithmetic.RecodeSignedWindows.
internal static class SM9Windows
{
	// The number of digits of width w for scalars below 2^bits: ⌊bits/w⌋ + 1, the last holding the top bits mod w and the carry into them.
	internal static int DigitCount(int bits, int width)
	{
		return bits / width + 1;
	}
}
