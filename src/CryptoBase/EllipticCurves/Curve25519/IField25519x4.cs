namespace CryptoBase.EllipticCurves.Curve25519;

// Four field elements, one in each lane A, B, C, D, with the conversions, the negations and the ladder steps that Curve25519Vector takes besides the point formulas.
internal interface IField25519x4<TSelf> : IEdwardsField25519x4<TSelf> where TSelf : struct, IField25519x4<TSelf>
{
	// (a, b, c, d) for tight elements, reduced.
	static abstract void Create(in Field25519 a, in Field25519 b, in Field25519 c, in Field25519 d, out TSelf result);

	// The four lanes of a value that a product gives, as tight elements.
	static abstract void Extract(in TSelf value, out Field25519 a, out Field25519 b, out Field25519 c, out Field25519 d);

	// The cached form (y − x, y + x, 2, 2dxy) of EdwardsBaseTable.Select(window, digit), its lookup and conversion kept in registers. Neither the time nor the addresses read depend on digit. Lane D is reduced or the negation of a reduced lane, and the others reduced.
	static abstract void SelectBase(int window, int digit, out TSelf result);

	// (Y − X, Y + X, Z, T) from a reduced (X, Y, Z, T).
	static abstract void DiffSum(in TSelf point, out TSelf result);

	// (a·A, b·B, c·C, d·D) for constants below 2^18 and the results of DiffSum, reduced.
	static abstract void MultiplySmall(in TSelf value, uint a, uint b, uint c, uint d, out TSelf result);

	// (A, B, C, −D) for a reduced value, and the negation of a cached point, (B, A, C, −D), for a cached point whose lane D is reduced or the negation of a reduced lane.
	static abstract void NegateD(in TSelf value, out TSelf result);

	static abstract void NegateCached(in TSelf value, out TSelf result);

	// The operands of the second product of a step from a reduced ladder state (x2, z2, x3, z3), first swapped to (x3, z3, x2, z2) where swap is set, which is 0 or ulong.MaxValue: with A = x2 + z2, B = x2 − z2, C = x3 + z3 and D = x3 − z3, the first product is (A², B², DA, CB) = (AA, BB, DA, CB), and the operands are (AA, E, DA + CB, DA − CB) and (BB, AA + a24·E, DA + CB, DA − CB), with E = AA − BB.
	static abstract void LadderOperands(in TSelf state, ulong swap, out TSelf left, out TSelf right);

	// The number of values that the multiplier of the ladder takes.
	static abstract int MultiplierLength { get; }

	// The multiplier of the ladder from u, which must be tight, in MultiplierLength values: (1, 1, 1, u) in whatever form LadderProducts takes it.
	static abstract void CreateMultiplier(in Field25519 u, Span<TSelf> multiplier);

	// left·right·(1, 1, 1, u), the last two products of a step, for the operands of LadderOperands and the first of the values of CreateMultiplier; a reduced value.
	static abstract void LadderProducts(in TSelf left, in TSelf right, in TSelf multiplier, out TSelf result);

	// Swaps (A, B) with (C, D) where mask is set; mask is 0 or ulong.MaxValue.
	static abstract void ConditionalSwapHalves(ulong mask, ref TSelf value);
}
