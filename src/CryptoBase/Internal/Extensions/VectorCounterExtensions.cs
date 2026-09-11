namespace CryptoBase.Internal.Extensions;

internal static class VectorCounterExtensions
{
	extension<T>(Vector128<T> nonce)
	{
		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public Vector128<T> IncUInt128LE()
		{
			Vector128<long> v = nonce.AsInt64();
			Vector128<long> m1 = Vector128.Create(-1L, 0L);

			Vector128<long> carry = Vector128.Equals(v, m1);

			carry = Sse2.ShiftLeftLogical128BitLane(carry, 8);

			v -= m1;
			v -= carry;

			return v.As<long, T>();
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public Vector128<T> IncUInt32LE()
		{
			return (nonce.AsUInt32() + Vector128.Create(1u, 0, 0, 0)).As<uint, T>();
		}
	}

	extension<T>(Vector256<T> nonce)
	{
		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public Vector256<T> AddUInt128LE22()
		{
			Vector256<long> v = nonce.AsInt64();
			Vector256<long> signBit = Vector256.Create(long.MinValue);
			Vector256<long> thrX = Vector256.Create(Vector128.Create(long.MaxValue - 2, long.MaxValue));

			Vector256<long> sum = v + Vector256.Create(Vector128.Create(2L, 0L));

			Vector256<long> vX = v ^ signBit;
			Vector256<long> carry = Vector256.GreaterThan(vX, thrX);
			carry = Avx2.ShiftLeftLogical128BitLane(carry, 8);

			return (sum - carry).As<long, T>();
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public Vector256<T> AddUInt32LE22()
		{
			return (nonce.AsUInt32() + Vector256.Create(Vector128.Create(2u, 0, 0, 0))).As<uint, T>();
		}

		/// <summary>
		/// Increments the upper 128-bit little-endian integer. Note that this is only applicable when the lower part is nonzero during carry propagation.
		/// For a general implementation:
		/// var carry = Vector256.Equals(v, Vector256.Create(-1L)); carry &amp;= vMinusUpper128LE;
		/// </summary>
		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public Vector256<T> AddUInt128LE01()
		{
			Vector256<long> v = nonce.AsInt64();

			Vector256<long> vMinusUpper128LE = Vector256.Create(0, 0, -1, 0);
			Vector256<long> carry = Vector256.Equals(v, vMinusUpper128LE);
			carry = Avx2.ShiftLeftLogical128BitLane(carry, 8);

			v -= vMinusUpper128LE;
			return (v - carry).As<long, T>();
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public Vector256<T> AddUInt32LE01()
		{
			return (nonce.AsUInt32() + Vector256.Create(0u, 0, 0, 0, 1u, 0, 0, 0)).As<uint, T>();
		}
	}

	extension<T>(Vector512<T> nonce)
	{
		/// <summary>
		/// [v0,v1,v2,v3] => [v0+4,v1+4,v2+4,v3+4]
		/// </summary>
		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public Vector512<T> AddUInt128LE4444()
		{
			Vector512<ulong> v = nonce.AsUInt64();
			Vector512<ulong> thr = Vector512.Create
			(
				ulong.MaxValue - 4UL, 0xFFFF_FFFF_FFFF_FFFFUL,
				ulong.MaxValue - 4UL, 0xFFFF_FFFF_FFFF_FFFFUL,
				ulong.MaxValue - 4UL, 0xFFFF_FFFF_FFFF_FFFFUL,
				ulong.MaxValue - 4UL, 0xFFFF_FFFF_FFFF_FFFFUL
			);

			Vector512<ulong> sum = v + Vector512.Create(4UL, 0, 4, 0, 4, 0, 4, 0);

			Vector512<ulong> carry = Vector512.GreaterThan(v, thr);
			carry = Avx512BW.ShiftLeftLogical128BitLane(carry.AsByte(), 8).AsUInt64();

			return (sum - carry).As<ulong, T>();
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public Vector512<T> AddUInt32LE4444()
		{
			return (nonce.AsUInt32() + Vector512.Create(4u, 0, 0, 0, 4u, 0, 0, 0, 4u, 0, 0, 0, 4u, 0, 0, 0)).As<uint, T>();
		}

		/// <summary>
		/// [v0,v1,v2,v3] => [v0+0,v1+1,v2+2,v3+3]
		/// </summary>
		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public Vector512<T> AddUInt128LE0123()
		{
			Vector512<ulong> v = nonce.AsUInt64();
			Vector512<ulong> thr = Vector512.Create
			(
				ulong.MaxValue - 0UL, 0xFFFF_FFFF_FFFF_FFFFUL,
				ulong.MaxValue - 1UL, 0xFFFF_FFFF_FFFF_FFFFUL,
				ulong.MaxValue - 2UL, 0xFFFF_FFFF_FFFF_FFFFUL,
				ulong.MaxValue - 3UL, 0xFFFF_FFFF_FFFF_FFFFUL
			);

			Vector512<ulong> sum = v + Vector512.Create(0UL, 0, 1, 0, 2, 0, 3, 0);

			Vector512<ulong> carry = Vector512.GreaterThan(v, thr);
			carry = Avx512BW.ShiftLeftLogical128BitLane(carry.AsByte(), 8).AsUInt64();

			return (sum - carry).As<ulong, T>();
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public Vector512<T> AddUInt32LE0123()
		{
			return (nonce.AsUInt32() + Vector512.Create(0u, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0)).As<uint, T>();
		}
	}
}
