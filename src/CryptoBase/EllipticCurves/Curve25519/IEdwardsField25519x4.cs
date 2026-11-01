namespace CryptoBase.EllipticCurves.Curve25519;

// The products of the parallel point formulas, on field elements in lanes A, B, C, D, as EdwardsLanes takes them. Each implementation bounds the limbs of a reduced value, which every product gives, and of the lazy sums and differences that its steps give between the products, so that each product takes what the step before gives. None branches on or indexes by a value.
internal interface IEdwardsField25519x4<TSelf> where TSelf : struct, IEdwardsField25519x4<TSelf>
{
	static abstract bool IsSupported { get; }

	// The lane products. left may be any left operand that AddOperands or DoubleOperands gives, right any right one, a cached point or a reduced value.
	static abstract void Multiply(in TSelf left, in TSelf right, out TSelf result);

	// The operands of the last product of a readdition of a reduced (X, Y, Z, T) and a cached point: from (S8, S9, S10, S11) = (Y − X, Y + X, Z, T)·cached, (S12, S15, S15, S12) and (S14, S13, S14, S13), with S12 = S9 − S8, S13 = S9 + S8, S14 = S10 − S11 and S15 = S10 + S11.
	static abstract void AddOperands(in TSelf point, in TSelf cached, out TSelf left, out TSelf right);

	// The operands of the last product of a doubling of a reduced (X, Y, Z, T): from (S1, S2, S3, −S4) = (X², Y², Z², −(X + Y)²), (S8, S5, S8, S5) and (S9, S6, S6, S9), with S5 = S1 + S2, S6 = S1 − S2, S8 = S6 + 2S3 and S9 = S5 − S4.
	static abstract void DoubleOperands(in TSelf point, out TSelf left, out TSelf right);
}
