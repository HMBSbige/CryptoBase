namespace CryptoBase.EllipticCurves.Curve448;

// The point formulas of Edwards448Vector, on reduced points (X, Y, Z, T) in lanes A to D. Each addition and doubling takes two lane products (Hisil, Wong, Carter and Dawson, "Twisted Edwards curves revisited", 2008, §3 and §4): the first gives the four products of the formula's first round, the second the coordinates of the result. scratch holds ScratchLength values in whatever form the products take, and SelectBase and LoadAffine write the right operand of an addition there.
internal interface IEdwardsField448x4<TSelf> : IField448x4<TSelf> where TSelf : unmanaged, IEdwardsField448x4<TSelf>
{
	// Writes entry index of comb of TwistedBaseTable into scratch for TwistedAdd: (y − x, y + x, 2, 2d'xy), or (y + x, y − x, 2, −2d'xy), its negation, where negative is set, which is 0 or ulong.MaxValue. Neither the time nor the addresses read depend on index or negative.
	static abstract void SelectBase(int comb, uint index, ulong negative, ref TSelf scratch);

	// point + the entry in scratch on the twisted curve −x² + y² = 1 + d'x²y², whose a = −1 keeps every lane of both products busy.
	static abstract void TwistedAdd(ref TSelf point, ref TSelf scratch);

	// 2·point on the twisted curve.
	static abstract void TwistedDouble(ref TSelf point, ref TSelf scratch);

	// Writes (x, y, dxy, x + y) of a public affine point of edwards448 into scratch for Add, or those of its negation, (−x, y, −dxy, y − x), where negative is set.
	static abstract void LoadAffine(in EdwardsAffinePoint point, bool negative, ref TSelf scratch);

	// point + the affine point in scratch on edwards448. As Z2 = 1, the first round is the four products X1x2, Y1y2, T1·dx2y2 and (X1 + Y1)(x2 + y2).
	static abstract void Add(ref TSelf point, ref TSelf scratch);

	// 2·point on edwards448.
	static abstract void Double(ref TSelf point, ref TSelf scratch);
}
