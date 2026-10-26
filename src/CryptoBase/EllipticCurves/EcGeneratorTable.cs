namespace CryptoBase.EllipticCurves;

// Window i holds j·2^(wi)·G for j from 1 to 2^(w − 1), w = GeneratorWindowWidth.
internal static class EcGeneratorTable<TCurve, TField, TOrder>
	where TCurve : struct, IEcCurve
	where TField : unmanaged, IEcField<TField>
	where TOrder : unmanaged, IMontgomeryModulus
{
	internal static readonly AffinePoint<TField>[] Entries = Build();

	internal static int WindowCount => EcGroup<TCurve, TField, TOrder>.DigitCount(TCurve.GeneratorWindowWidth);

	internal static int WindowLength => 1 << TCurve.GeneratorWindowWidth - 1;

	// The base B of a window doubles into 2B, and each later entry j·B, j ≥ 3, is (j − 1)·B + B, two points that are neither equal, opposite nor at infinity.
	private static AffinePoint<TField>[] Build()
	{
		Debug.Assert(WindowLength >= 2);

		JacobianPoint<TField>[] multiples = new JacobianPoint<TField>[WindowCount * WindowLength];
		EcGroup<TCurve, TField, TOrder>.Generator(out AffinePoint<TField> generator);
		JacobianPoint<TField>.FromAffine(in generator, out JacobianPoint<TField> windowBase);

		for (int i = 0; i < multiples.Length; i += WindowLength)
		{
			multiples[i] = windowBase;
			EcGroup<TCurve, TField, TOrder>.Double(in windowBase, out multiples[i + 1]);

			for (int j = 2; j < WindowLength; ++j)
			{
				_ = EcGroup<TCurve, TField, TOrder>.AddDistinct(in multiples[i + j - 1], in windowBase, out multiples[i + j]);
			}

			// The last entry is 2^(w − 1) times the base, so its double is the base of the next window.
			EcGroup<TCurve, TField, TOrder>.Double(in multiples[i + WindowLength - 1], out windowBase);
		}

		AffinePoint<TField>[] entries = new AffinePoint<TField>[multiples.Length];
		EcGroup<TCurve, TField, TOrder>.ToAffineVariableTime(multiples, entries);
		return entries;
	}
}
