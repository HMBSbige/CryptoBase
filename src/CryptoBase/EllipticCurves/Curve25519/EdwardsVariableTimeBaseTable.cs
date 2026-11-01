namespace CryptoBase.EllipticCurves.Curve25519;

// The odd multiples B, 3B, …, (2^(w − 1) − 1)·B for the NAF of width w = Width.
internal static class EdwardsVariableTimeBaseTable
{
	internal const int Width = 8;

	internal static readonly EdwardsNielsPoint[] Entries = Build();

	// Each entry after B is (j − 2)·B + 2B for odd j ≥ 3.
	private static EdwardsNielsPoint[] Build()
	{
		EdwardsPoint[] multiples = new EdwardsPoint[1 << Width - 2];
		multiples[0] = Edwards25519.Base;
		Edwards25519.Double(in Edwards25519.Base, out EdwardsPoint twice);
		Edwards25519.ToCached(in twice, out EdwardsCachedPoint cached);

		for (int j = 1; j < multiples.Length; ++j)
		{
			Edwards25519.Add(in multiples[j - 1], in cached, out EdwardsCompletedPoint sum);
			Edwards25519.ToExtended(in sum, out multiples[j]);
		}

		EdwardsNielsPoint[] entries = new EdwardsNielsPoint[multiples.Length];
		Edwards25519.ToNielsVariableTime(multiples, entries);
		return entries;
	}
}
