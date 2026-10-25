namespace CryptoBase.EllipticCurves;

// The odd multiples G, 3G, …, (2^(w − 1) − 1)·G for the NAF of width w = Width.
internal static class EcVariableTimeGeneratorTable<TCurve, TField, TOrder>
	where TCurve : struct, IEcCurve
	where TField : unmanaged, IMontgomeryModulus
	where TOrder : unmanaged, IMontgomeryModulus
{
	internal const int Width = 8;

	internal static readonly AffinePoint<TField>[] Entries = Build();

	// Each entry after G is (j − 2)·G + 2G for odd j ≥ 3, two points that are neither equal, opposite nor at infinity.
	private static AffinePoint<TField>[] Build()
	{
		JacobianPoint<TField>[] multiples = new JacobianPoint<TField>[1 << Width - 2];
		AffinePoint<TField> generator = new() { X = FieldElement<TField>.FromLimbs(TCurve.GeneratorX), Y = FieldElement<TField>.FromLimbs(TCurve.GeneratorY) };
		JacobianPoint<TField>.FromAffine(in generator, out multiples[0]);
		EcGroup<TCurve, TField, TOrder>.Double(in multiples[0], out JacobianPoint<TField> twice);

		for (int j = 1; j < multiples.Length; ++j)
		{
			_ = EcGroup<TCurve, TField, TOrder>.AddDistinct(in multiples[j - 1], in twice, out multiples[j]);
		}

		AffinePoint<TField>[] entries = new AffinePoint<TField>[multiples.Length];
		EcGroup<TCurve, TField, TOrder>.ToAffine(multiples, entries);
		return entries;
	}
}
