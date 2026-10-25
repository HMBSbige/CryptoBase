namespace CryptoBase.EllipticCurves;

internal readonly struct LimbVector256(Vector256<ulong> value) : ILimbVector<LimbVector256>
{
	private readonly Vector256<ulong> _value = value;

	public static int Count => Vector256<ulong>.Count;

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static LimbVector256 Create(ulong value)
	{
		return new LimbVector256(Vector256.Create(value));
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public void Store(ref ulong destination)
	{
		_value.StoreUnsafe(ref destination);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static LimbVector256 operator +(LimbVector256 left, LimbVector256 right)
	{
		return new LimbVector256(left._value + right._value);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static LimbVector256 MergeWhereEqual(LimbVector256 accumulator, LimbVector256 position, LimbVector256 target, ref readonly ulong source)
	{
		return new LimbVector256(Vector256.ConditionalSelect(Vector256.Equals(position._value, target._value), Vector256.LoadUnsafe(in source), accumulator._value));
	}
}
