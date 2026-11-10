namespace CryptoBase.EllipticCurves.Curve448;

// The arithmetic of Field448Blocks on the 64-bit lanes of a TVector, each a limb or a column of a product. Static members on the vectors rather than a wrapper type with operators: each result of a wrapper takes a local, too many for SquareProduct to inline its terms, and a wrapper operand in memory takes a load rather than folding into the multiplication.
internal interface IField448Vector<TVector> where TVector : unmanaged
{
	static abstract TVector Create(ulong value);

	static abstract TVector Add(TVector left, TVector right);

	static abstract TVector Subtract(TVector left, TVector right);

	static abstract TVector And(TVector left, TVector right);

	static abstract TVector Xor(TVector left, TVector right);

	static abstract TVector ShiftRight(TVector value, int shift);

	// addend + the low 32 bits of each lane of left times those of right, a 64-bit product.
	static abstract TVector MultiplyAdd(TVector addend, TVector left, TVector right);
}
