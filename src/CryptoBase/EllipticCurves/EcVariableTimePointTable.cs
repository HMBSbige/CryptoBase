namespace CryptoBase.EllipticCurves;

// For a public point Q. The N = TOrder.BitLength bits of a scalar split into PartCount parts of L = PartLength bits, and part c holds the odd multiples B, 3B, …, (2^(w − 1) − 1)·B of B = 2^(cL)·Q for the NAF of width w = Width, so that a product with Q takes L doublings instead of N.
internal static class EcVariableTimePointTable<TCurve, TField, TOrder>
	where TCurve : struct, IEcCurve
	where TField : unmanaged, IMontgomeryModulus
	where TOrder : unmanaged, IMontgomeryModulus
{
	internal const int Width = 5;

	internal const int PartCount = 16;

	internal static int PartLength => (TOrder.BitLength + PartCount - 1) / PartCount;

	internal static int PartEntryCount => 1 << Width - 2;

	internal static int Length => PartCount * PartEntryCount;

	// One chain of doublings gives each base B and its double, which are made affine together, so that each later entry (j + 2)·B = j·B + 2B is a mixed addition. The two points are neither equal, opposite nor at infinity, as j + 2 < n.
	internal static AffinePoint<TField>[] Build(in AffinePoint<TField> point)
	{
		Debug.Assert(PartLength >= 2);

		JacobianPoint<TField>[] bases = new JacobianPoint<TField>[2 * PartCount];
		JacobianPoint<TField>.FromAffine(in point, out bases[0]);
		EcGroup<TCurve, TField, TOrder>.Double(in bases[0], out bases[1]);

		for (int i = 2; i < bases.Length; i += 2)
		{
			// The double of the previous base is 2^(1 + (i/2 − 1)L)·Q, L − 1 doublings below this base.
			EcGroup<TCurve, TField, TOrder>.Double(in bases[i - 1], out bases[i]);

			for (int k = 2; k < PartLength; ++k)
			{
				EcGroup<TCurve, TField, TOrder>.Double(in bases[i], out bases[i]);
			}

			EcGroup<TCurve, TField, TOrder>.Double(in bases[i], out bases[i + 1]);
		}

		AffinePoint<TField>[] affineBases = new AffinePoint<TField>[bases.Length];
		EcGroup<TCurve, TField, TOrder>.ToAffine(bases, affineBases);
		JacobianPoint<TField>[] multiples = new JacobianPoint<TField>[Length];

		for (int c = 0; c < PartCount; ++c)
		{
			int first = c * PartEntryCount;
			JacobianPoint<TField>.FromAffine(in affineBases[2 * c], out multiples[first]);

			for (int j = first + 1; j < first + PartEntryCount; ++j)
			{
				_ = EcGroup<TCurve, TField, TOrder>.AddDistinct(in multiples[j - 1], in affineBases[2 * c + 1], out multiples[j]);
			}
		}

		AffinePoint<TField>[] entries = new AffinePoint<TField>[Length];
		EcGroup<TCurve, TField, TOrder>.ToAffine(multiples, entries);
		return entries;
	}
}
