namespace CryptoBase.EllipticCurves;

// Window i holds j·2^(wi)·G for j from 1 to 2^(w − 1), w = GeneratorWindowWidth.
internal static class EcGeneratorTable<TCurve, TField, TOrder>
	where TCurve : struct, IEcCurve
	where TField : unmanaged, IMontgomeryModulus
	where TOrder : unmanaged, IMontgomeryModulus
{
	internal static readonly AffinePoint<TField>[] Entries = Build();

	internal static int WindowCount => EcGroup<TCurve, TField, TOrder>.DigitCount(TCurve.GeneratorWindowWidth);

	internal static int WindowLength => 1 << TCurve.GeneratorWindowWidth - 1;

	private static AffinePoint<TField>[] Build()
	{
		ProjectivePoint<TField>[] multiples = new ProjectivePoint<TField>[WindowCount * WindowLength];
		AffinePoint<TField> generator = new() { X = FieldElement<TField>.FromLimbs(TCurve.GeneratorX), Y = FieldElement<TField>.FromLimbs(TCurve.GeneratorY) };
		ProjectivePoint<TField>.FromAffine(in generator, out ProjectivePoint<TField> windowBase);

		for (int i = 0; i < multiples.Length; i += WindowLength)
		{
			multiples[i] = windowBase;

			for (int j = 1; j < WindowLength; ++j)
			{
				EcGroup<TCurve, TField, TOrder>.Add(in multiples[i + j - 1], in windowBase, out multiples[i + j]);
			}

			// The last entry is 2^(w − 1) times the base, so its double is the base of the next window.
			EcGroup<TCurve, TField, TOrder>.Double(in multiples[i + WindowLength - 1], out windowBase);
		}

		AffinePoint<TField>[] entries = new AffinePoint<TField>[multiples.Length];
		EcGroup<TCurve, TField, TOrder>.ToAffine(multiples, entries);
		return entries;
	}
}
