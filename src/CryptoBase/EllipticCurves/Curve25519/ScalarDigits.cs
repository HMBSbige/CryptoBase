namespace CryptoBase.EllipticCurves.Curve25519;

// Digit expansions of scalars of 32 little-endian bytes, which are read as four 64-bit limbs.
internal static class ScalarDigits
{
	internal const int LimbCount = 4;

	internal static void ReadLimbs(ReadOnlySpan<byte> scalar, Span<ulong> limbs)
	{
		Debug.Assert(scalar.Length is 8 * LimbCount && limbs.Length is LimbCount);

		limbs[0] = BinaryPrimitives.ReadUInt64LittleEndian(scalar);
		limbs[1] = BinaryPrimitives.ReadUInt64LittleEndian(scalar.Slice(8));
		limbs[2] = BinaryPrimitives.ReadUInt64LittleEndian(scalar.Slice(16));
		limbs[3] = BinaryPrimitives.ReadUInt64LittleEndian(scalar.Slice(24));
	}

	// The digit beyond ⌊256/w⌋ holds the top 256 mod w bits, if any, and the carry into them.
	internal static int SignedWindowCount(int width)
	{
		return 256 / width + 1;
	}
}
