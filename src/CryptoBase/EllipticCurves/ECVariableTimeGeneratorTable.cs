namespace CryptoBase.EllipticCurves;

// The odd multiples G, 3G, …, (2^(w − 1) − 1)·G for the NAF of width w = Width.
internal static class ECVariableTimeGeneratorTable<TCurve, TField, TOrder>
	where TCurve : struct, IECCurve
	where TField : unmanaged, IECField<TField>
	where TOrder : unmanaged, IMontgomeryModulus
{
	internal const int Width = 8;

	internal static readonly AffinePoint<TField>[] Entries = Build();

	private static AffinePoint<TField>[] Build()
	{
		AffinePoint<TField>[] entries = new AffinePoint<TField>[1 << Width - 2];
		ECGroup<TCurve, TField, TOrder>.Generator(out AffinePoint<TField> generator);
		ECVariableTimeGroup<TCurve, TField, TOrder>.BuildOddMultiples(in generator, entries);
		return entries;
	}
}
