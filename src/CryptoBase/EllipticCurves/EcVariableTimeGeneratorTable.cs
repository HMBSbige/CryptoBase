namespace CryptoBase.EllipticCurves;

// The odd multiples G, 3G, …, (2^(w − 1) − 1)·G for the NAF of width w = Width.
internal static class EcVariableTimeGeneratorTable<TCurve, TField, TOrder>
	where TCurve : struct, IEcCurve
	where TField : unmanaged, IMontgomeryModulus
	where TOrder : unmanaged, IMontgomeryModulus
{
	internal const int Width = 8;

	internal static readonly AffinePoint<TField>[] Entries = Build();

	private static AffinePoint<TField>[] Build()
	{
		ProjectivePoint<TField>[] multiples = new ProjectivePoint<TField>[1 << Width - 2];
		AffinePoint<TField> generator = new() { X = FieldElement<TField>.FromLimbs(TCurve.GeneratorX), Y = FieldElement<TField>.FromLimbs(TCurve.GeneratorY) };
		ProjectivePoint<TField>.FromAffine(in generator, out multiples[0]);
		EcGroup<TCurve, TField, TOrder>.Double(in multiples[0], out ProjectivePoint<TField> twice);

		for (int j = 1; j < multiples.Length; ++j)
		{
			EcGroup<TCurve, TField, TOrder>.Add(in multiples[j - 1], in twice, out multiples[j]);
		}

		AffinePoint<TField>[] entries = new AffinePoint<TField>[multiples.Length];
		EcGroup<TCurve, TField, TOrder>.ToAffine(multiples, entries);
		return entries;
	}
}
