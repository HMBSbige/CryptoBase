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

			if (Sse2.IsSupported)
			{
				carry = Sse2.ShiftLeftLogical128BitLane(carry, 8);
			}
			else if (AdvSimd.IsSupported)
			{
				carry = AdvSimd.ExtractVector128(Vector128<long>.Zero, carry, 1);
			}
			else
			{
				carry = Vector128.Create(0L, carry.GetElement(0));
			}

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
			Vector256<ulong> counters = nonce.AsUInt64();
			Vector256<ulong> sum = counters + Vector256.Create(Vector128.Create(2UL, 0UL));

			Vector256<ulong> carry = Vector256.Equals(counters >>> 1, Vector256.Create(ulong.MaxValue >> 1));
			carry = Avx2.ShiftLeftLogical128BitLane(carry, 8);

			return (sum - carry).As<ulong, T>();
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public Vector256<T> AddUInt32LE22()
		{
			return (nonce.AsUInt32() + Vector256.Create(Vector128.Create(2u, 0, 0, 0))).As<uint, T>();
		}

		// Increments only the upper 128-bit little-endian integer.
		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public Vector256<T> AddUInt128LE01()
		{
			Vector256<long> v = nonce.AsInt64();

			Vector256<long> vMinusUpper128LE = Vector256.Create(0, 0, -1, 0);
			Vector256<long> carry = Vector256.Equals(v, vMinusUpper128LE) & vMinusUpper128LE;
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
		// [v0,v1,v2,v3] => [v0+4,v1+4,v2+4,v3+4]
		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public Vector512<T> AddUInt128LE4444()
		{
			return AddUInt128LE(nonce.AsUInt64(), Vector512.Create(4UL, 0, 4, 0, 4, 0, 4, 0)).As<ulong, T>();
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public Vector512<T> AddUInt32LE4444()
		{
			return (nonce.AsUInt32() + Vector512.Create(4u, 0, 0, 0, 4u, 0, 0, 0, 4u, 0, 0, 0, 4u, 0, 0, 0)).As<uint, T>();
		}

		// [v0,v1,v2,v3] => [v0+0,v1+1,v2+2,v3+3]
		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public Vector512<T> AddUInt128LE0123()
		{
			return AddUInt128LE(nonce.AsUInt64(), Vector512.Create(0UL, 0, 1, 0, 2, 0, 3, 0)).As<ulong, T>();
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public Vector512<T> AddUInt32LE0123()
		{
			return (nonce.AsUInt32() + Vector512.Create(0u, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0)).As<uint, T>();
		}
	}

	// Adds an increment whose high halves are zero to each 128-bit lane; a low half overflows exactly when it exceeds the complement of its increment.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector512<ulong> AddUInt128LE(Vector512<ulong> value, Vector512<ulong> increment)
	{
		Vector512<ulong> sum = value + increment;

		Vector512<ulong> carry = Vector512.GreaterThan(value, ~increment);
		carry = Avx512BW.ShiftLeftLogical128BitLane(carry.AsByte(), 8).AsUInt64();

		return sum - carry;
	}
}
