namespace CryptoBase.EllipticCurves;

internal readonly struct LimbVector128(Vector128<ulong> value) : ILimbVector<LimbVector128>
{
	private readonly Vector128<ulong> _value = value;

	public static int Count => Vector128<ulong>.Count;

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static LimbVector128 Create(ulong value)
	{
		return new LimbVector128(Vector128.Create(value));
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public void Store(ref ulong destination)
	{
		_value.StoreUnsafe(ref destination);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static LimbVector128 operator +(LimbVector128 left, LimbVector128 right)
	{
		return new LimbVector128(left._value + right._value);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static LimbVector128 MergeWhereEqual(LimbVector128 accumulator, LimbVector128 position, LimbVector128 target, ref readonly ulong source)
	{
		return new LimbVector128(Vector128.ConditionalSelect(Vector128.Equals(position._value, target._value), Vector128.LoadUnsafe(in source), accumulator._value));
	}
}
