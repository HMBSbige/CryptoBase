namespace CryptoBase.EllipticCurves;

internal interface ILimbVector<TSelf> where TSelf : struct, ILimbVector<TSelf>
{
	static abstract int Count { get; }

	static abstract TSelf Create(ulong value);

	static abstract TSelf Load(ref readonly ulong source);

	void Store(ref ulong destination);

	// ulong.MaxValue in the limbs where left and right are equal and 0 elsewhere.
	static abstract TSelf Equal(TSelf left, TSelf right);

	static abstract TSelf operator +(TSelf left, TSelf right);

	static abstract TSelf operator &(TSelf left, TSelf right);

	static abstract TSelf operator |(TSelf left, TSelf right);
}
