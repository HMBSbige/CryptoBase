namespace CryptoBase.EllipticCurves.SM9;

internal readonly struct SM9VectorAvx2 : ISM9Vector<SM9VectorAvx2>
{
	private readonly Vector256<ulong> _value;

	private SM9VectorAvx2(Vector256<ulong> value)
	{
		_value = value;
	}

	public static bool IsSupported => Avx2.IsSupported && Vector256.IsHardwareAccelerated;

	public static int Count => Vector256<ulong>.Count;

	public static int RegisterCount => 16;

	public static SM9VectorAvx2 Zero => default;

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static SM9VectorAvx2 Create(ulong value)
	{
		return new SM9VectorAvx2(Vector256.Create(value));
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static SM9VectorAvx2 Load(ref readonly ulong source)
	{
		return new SM9VectorAvx2(Vector256.LoadUnsafe(in source));
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static SM9VectorAvx2 LoadBroadcast(ref readonly ulong source)
	{
		return new SM9VectorAvx2(Vector256.Create(source));
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static unsafe SM9VectorAvx2 LoadPairBroadcast(ref readonly ulong source)
	{
		return new SM9VectorAvx2(Avx2.BroadcastVector128ToVector256((ulong*)Unsafe.AsPointer(ref Unsafe.AsRef(in source))));
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public void Store(ref ulong destination)
	{
		_value.StoreUnsafe(ref destination);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static SM9VectorAvx2 operator +(SM9VectorAvx2 left, SM9VectorAvx2 right)
	{
		return new SM9VectorAvx2(left._value + right._value);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static SM9VectorAvx2 operator -(SM9VectorAvx2 left, SM9VectorAvx2 right)
	{
		return new SM9VectorAvx2(left._value - right._value);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static SM9VectorAvx2 operator &(SM9VectorAvx2 left, SM9VectorAvx2 right)
	{
		return new SM9VectorAvx2(left._value & right._value);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static SM9VectorAvx2 operator |(SM9VectorAvx2 left, SM9VectorAvx2 right)
	{
		return new SM9VectorAvx2(left._value | right._value);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static SM9VectorAvx2 operator <<(SM9VectorAvx2 value, int shift)
	{
		return new SM9VectorAvx2(value._value << shift);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static SM9VectorAvx2 operator >>>(SM9VectorAvx2 value, int shift)
	{
		return new SM9VectorAvx2(value._value >>> shift);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static SM9VectorAvx2 Multiply(SM9VectorAvx2 left, SM9VectorAvx2 right)
	{
		return new SM9VectorAvx2(Avx2.Multiply(left._value.AsUInt32(), right._value.AsUInt32()));
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static SM9VectorAvx2 MultiplyAdd(SM9VectorAvx2 addend, SM9VectorAvx2 left, SM9VectorAvx2 right)
	{
		return addend + Multiply(left, right);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static SM9VectorAvx2 MultiplyByFactor(SM9VectorAvx2 left, uint factor)
	{
		return Multiply(left, Create(factor));
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static SM9VectorAvx2 MultiplyAddByFactor(SM9VectorAvx2 addend, SM9VectorAvx2 left, uint factor)
	{
		return addend + Multiply(left, Create(factor));
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static SM9VectorAvx2 ShiftRightArithmetic26(SM9VectorAvx2 value)
	{
		if (Avx512F.VL.IsSupported)
		{
			return new SM9VectorAvx2(Avx512F.VL.ShiftRightArithmetic(value._value.AsInt64(), 26).AsUInt64());
		}

		// AVX2 has no arithmetic shift of 64-bit lanes: with the sign bit flipped the value is offset by 2^63, which the logical shift takes to 2^37.
		return new SM9VectorAvx2(((value._value ^ Vector256.Create(1UL << 63)) >>> 26) - Vector256.Create(1UL << 37));
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static SM9VectorAvx2 ConditionalSelect(SM9VectorAvx2 mask, SM9VectorAvx2 whenSet, SM9VectorAvx2 whenClear)
	{
		return new SM9VectorAvx2(Vector256.ConditionalSelect(mask._value, whenSet._value, whenClear._value));
	}

	// Each half of the destination row from the four vectors of the two rows: one vpermd of each source it takes, blended by vpblendd. The pattern is a constant, so the indices, the masks and which sources a half takes all fold.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static void Permute(ref readonly ulong first, ref readonly ulong second, ref ulong destination, ulong pattern)
	{
		Vector256<uint> a = Vector256.LoadUnsafe(in first).AsUInt32();
		Vector256<uint> b = Vector256.LoadUnsafe(in Unsafe.Add(ref Unsafe.AsRef(in first), 4)).AsUInt32();
		Vector256<uint> c = Vector256.LoadUnsafe(in second).AsUInt32();
		Vector256<uint> d = Vector256.LoadUnsafe(in Unsafe.Add(ref Unsafe.AsRef(in second), 4)).AsUInt32();
		Vector256<uint> low = Gather(a, b, c, d, pattern & 0xFFFF);
		Vector256<uint> high = Gather(a, b, c, d, pattern >> 16 & 0xFFFF);
		low.AsUInt64().StoreUnsafe(ref destination);
		high.AsUInt64().StoreUnsafe(ref Unsafe.Add(ref destination, 4));
	}

	// Permute writes every lane already.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static void PermuteFull(ref readonly ulong first, ref readonly ulong second, ref ulong destination, ulong pattern)
	{
		Permute(in first, in second, ref destination, pattern);
	}

	// Lane j of four takes lane n_j & 3 of source n_j >> 2, n_j in bits 4j to 4j + 3 of half.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector256<uint> Gather(Vector256<uint> a, Vector256<uint> b, Vector256<uint> c, Vector256<uint> d, ulong half)
	{
		uint n0 = (uint)half & 15;
		uint n1 = (uint)(half >> 4) & 15;
		uint n2 = (uint)(half >> 8) & 15;
		uint n3 = (uint)(half >> 12) & 15;
		Vector256<uint> indices = Vector256.Create(2 * (n0 & 3), 2 * (n0 & 3) + 1, 2 * (n1 & 3), 2 * (n1 & 3) + 1, 2 * (n2 & 3), 2 * (n2 & 3) + 1, 2 * (n3 & 3), 2 * (n3 & 3) + 1);
		Vector256<uint> result = Vector256<uint>.Zero;
		result = Take(result, a, indices, Lanes(n0, n1, n2, n3, 0));
		result = Take(result, b, indices, Lanes(n0, n1, n2, n3, 1));
		result = Take(result, c, indices, Lanes(n0, n1, n2, n3, 2));
		return Take(result, d, indices, Lanes(n0, n1, n2, n3, 3));
	}

	// The vpblendd control of the lanes that take source k, two dwords each.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static byte Lanes(uint n0, uint n1, uint n2, uint n3, uint k)
	{
		return (byte)((n0 >> 2 == k ? 0x03 : 0) | (n1 >> 2 == k ? 0x0C : 0) | (n2 >> 2 == k ? 0x30 : 0) | (n3 >> 2 == k ? 0xC0 : 0));
	}

	// lanes folds to a constant once Permute is inlined with a constant pattern.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector256<uint> Take(Vector256<uint> result, Vector256<uint> source, Vector256<uint> indices, byte lanes)
	{
		if (lanes is 0)
		{
			return result;
		}

		if (lanes is 0xFF)
		{
			return Avx2.PermuteVar8x32(source, indices);
		}

#pragma warning disable CA1857
		// ReSharper disable once ConstantExpected
		return Avx2.Blend(result, Avx2.PermuteVar8x32(source, indices), lanes);
#pragma warning restore CA1857
	}

	// A row of eight lanes spans several vectors of this type, so the kernels never take this.
	public static SM9VectorAvx2 Permute(SM9VectorAvx2 first, SM9VectorAvx2 second, ulong pattern)
	{
		throw new UnreachableException();
	}

}
