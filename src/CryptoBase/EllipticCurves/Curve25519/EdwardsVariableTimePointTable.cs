namespace CryptoBase.EllipticCurves.Curve25519;

// For a public point A. The 256 bits of a scalar split into PartCount parts of L = PartLength bits, and part c holds the odd multiples P, 3P, …, (2^(w − 1) − 1)·P of P = 2^(cL)·A for the NAF of width w = Width, so that a product with A takes L doublings instead of 256.
internal static class EdwardsVariableTimePointTable
{
	internal const int Width = 5;

	internal const int PartCount = 16;

	internal const int PartLength = 256 / PartCount;

	internal const int PartEntryCount = 1 << Width - 2;

	internal const int Length = PartCount * PartEntryCount;

	// Each part starts at its base P and adds 2P; the double of a base, doubled L − 1 more times, is the next base.
	internal static EdwardsNielsPoint[] Build(in EdwardsPoint point)
	{
		EdwardsPoint[] multiples = new EdwardsPoint[Length];
		EdwardsPoint partBase = point;

		for (int c = 0; c < PartCount; ++c)
		{
			int first = c * PartEntryCount;
			multiples[first] = partBase;
			Edwards25519.Double(in partBase, out partBase);
			Edwards25519.ToCached(in partBase, out EdwardsCachedPoint twice);

			for (int j = first + 1; j < first + PartEntryCount; ++j)
			{
				Edwards25519.Add(in multiples[j - 1], in twice, out EdwardsCompletedPoint sum);
				Edwards25519.ToExtended(in sum, out multiples[j]);
			}

			for (int k = 1; k < PartLength; ++k)
			{
				Edwards25519.Double(in partBase, out partBase);
			}
		}

		EdwardsNielsPoint[] entries = new EdwardsNielsPoint[Length];
		Edwards25519.ToNielsVariableTime(multiples, entries);
		return entries;
	}
}
