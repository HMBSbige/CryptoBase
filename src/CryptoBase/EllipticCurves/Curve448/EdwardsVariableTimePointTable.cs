namespace CryptoBase.EllipticCurves.Curve448;

// For a public point A of edwards448, of any order. The 448 bits of a scalar split into PartCount parts of L = PartLength bits, and part c holds the odd multiples P, 3P, …, (2^(w − 1) − 1)·P of P = 2^(cL)·A for the NAF of width w = Width, so that a product with A takes L doublings instead of 448.
internal static class EdwardsVariableTimePointTable
{
	internal const int Width = 5;

	internal const int PartCount = 16;

	internal const int PartLength = 8 * Edwards448.ScalarLength / PartCount;

	internal const int PartEntryCount = 1 << Width - 2;

	internal const int Length = PartCount * PartEntryCount;

	internal static EdwardsAffinePoint[] Build(in EdwardsPoint point)
	{
		// The products with the table also read EdwardsVariableTimeBaseTable.Parts, and they are compiled once, with full optimization, as they allocate on the stack. Building Parts first lets the JIT take it as a constant.
		_ = EdwardsVariableTimeBaseTable.Parts;
		return Build(in point, Width);
	}

	// For a NAF of any width w. Each part starts at its base P and adds 2P; the double of a base, doubled L − 1 more times, is the next base, which the last part does not need.
	internal static EdwardsAffinePoint[] Build(in EdwardsPoint point, int width)
	{
		int partEntries = 1 << width - 2;
		EdwardsPoint[] multiples = new EdwardsPoint[PartCount * partEntries];
		EdwardsPoint partBase = point;

		for (int c = 0; c < PartCount; ++c)
		{
			int first = c * partEntries;
			multiples[first] = partBase;
			Edwards448.Double(in partBase, out partBase);
			Edwards448.ToCached(in partBase, out EdwardsCachedPoint twice);

			for (int j = first + 1; j < first + partEntries; ++j)
			{
				Edwards448.Add(in multiples[j - 1], in twice, out EdwardsCompletedPoint sum);
				Edwards448.ToExtended(in sum, out multiples[j]);
			}

			if (c < PartCount - 1)
			{
				for (int k = 1; k < PartLength; ++k)
				{
					Edwards448.Double(in partBase, out partBase);
				}
			}
		}

		EdwardsAffinePoint[] entries = new EdwardsAffinePoint[multiples.Length];
		Edwards448.ToAffineVariableTime(multiples, entries);
		return entries;
	}
}
