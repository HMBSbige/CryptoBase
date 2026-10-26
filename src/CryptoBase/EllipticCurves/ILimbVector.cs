namespace CryptoBase.EllipticCurves;

internal interface ILimbVector<TSelf> where TSelf : struct, ILimbVector<TSelf>
{
	static abstract int Count { get; }

	static abstract TSelf Create(ulong value);

	void Store(ref ulong destination);

	static abstract TSelf operator +(TSelf left, TSelf right);

	static abstract TSelf operator |(TSelf left, TSelf right);

	// The limbs at source where position and target are equal and accumulator elsewhere. accumulator must be 0 where they are equal, so that a blend and an OR both give the result. One member rather than a compare, a load and a blend lets the JIT keep the compare as a mask and fold the load into the blend.
	static abstract TSelf MergeWhereEqual(TSelf accumulator, TSelf position, TSelf target, ref readonly ulong source);
}
