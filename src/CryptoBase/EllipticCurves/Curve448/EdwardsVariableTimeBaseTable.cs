namespace CryptoBase.EllipticCurves.Curve448;

// Multiples of B on edwards448 for the variable-time double-base products. Entries holds the odd multiples B, 3B, …, (2^(w − 1) − 1)·B for the NAF of width w = Width of a whole scalar. Parts is the EdwardsVariableTimePointTable of B for the wider NAF of width PartWidth, so that the parts of a scalar share the doublings of a point table and take fewer additions.
internal static class EdwardsVariableTimeBaseTable
{
	internal const int Width = 8;

	internal const int PartWidth = 6;

	internal const int PartEntryCount = 1 << PartWidth - 2;

	internal static readonly EdwardsAffinePoint[] Entries = Build();

	internal static EdwardsAffinePoint[] Parts => PartTable.Entries;

	// Each entry after B is (j − 2)·B + 2B for odd j ≥ 3.
	private static EdwardsAffinePoint[] Build()
	{
		EdwardsPoint[] multiples = new EdwardsPoint[1 << Width - 2];
		multiples[0] = Edwards448.Base;
		Edwards448.Double(in Edwards448.Base, out EdwardsPoint twice);
		Edwards448.ToCached(in twice, out EdwardsCachedPoint cached);

		for (int j = 1; j < multiples.Length; ++j)
		{
			Edwards448.Add(in multiples[j - 1], in cached, out EdwardsCompletedPoint sum);
			Edwards448.ToExtended(in sum, out multiples[j]);
		}

		EdwardsAffinePoint[] entries = new EdwardsAffinePoint[multiples.Length];
		Edwards448.ToAffineVariableTime(multiples, entries);
		return entries;
	}

	// Only the products with a point table use Parts, so it has a type initializer of its own.
	private static class PartTable
	{
		internal static readonly EdwardsAffinePoint[] Entries = EdwardsVariableTimePointTable.Build(in Edwards448.Base, PartWidth);
	}
}
