namespace CryptoBase;

internal static class VectorCounterExtensions
{
	extension<T>(Vector128<T> nonce)
	{
		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public Vector128<T> IncUInt128Le()
		{
			Vector128<long> v = nonce.AsInt64();
			Vector128<long> m1 = Vector128.Create(-1L, 0L);

			Vector128<long> carry;

			if (Sse41.IsSupported)
			{
				carry = Sse41.CompareEqual(v, m1);
			}
			else
			{
				Vector128<int> eqFF32 = Sse2.CompareEqual(v.AsInt32(), Vector128<int>.AllBitsSet);
				Vector128<int> lowD0 = Sse2.Shuffle(eqFF32, 0x00);
				Vector128<int> lowD1 = Sse2.Shuffle(eqFF32, 0x55);
				carry = (lowD0 & lowD1).AsInt64();
			}

			carry = Sse2.ShiftLeftLogical128BitLane(carry, 8);

			v -= m1;
			v -= carry;

			return v.As<long, T>();
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public Vector128<T> IncUInt32Le()
		{
			return (nonce.AsUInt32() + Vector128.Create(1u, 0, 0, 0)).As<uint, T>();
		}
	}

	extension<T>(Vector256<T> nonce)
	{
		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public Vector256<T> AddUInt128Le22()
		{
			Vector256<long> v = nonce.AsInt64();
			Vector256<long> signBit = Vector256.Create(0x8000_0000_0000_0000UL).AsInt64();
			Vector256<long> thrX = Vector256.Create
			(
				ulong.MaxValue - 2UL ^ 0x8000_0000_0000_0000UL, ulong.MaxValue ^ 0x8000_0000_0000_0000UL,
				ulong.MaxValue - 2UL ^ 0x8000_0000_0000_0000UL, ulong.MaxValue ^ 0x8000_0000_0000_0000UL
			).AsInt64();

			Vector256<long> sum = v + Vector256.Create(2, 0, 2, 0);

			Vector256<long> vX = v ^ signBit;
			Vector256<long> carry = Avx2.CompareGreaterThan(vX, thrX);
			carry = Avx2.ShiftLeftLogical128BitLane(carry.AsByte(), 8).AsInt64();

			return (sum - carry).As<long, T>();
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public Vector256<T> AddUInt32Le22()
		{
			return (nonce.AsUInt32() + Vector256.Create(2u, 0, 0, 0, 2u, 0, 0, 0)).As<uint, T>();
		}

		/// <summary>
		/// 高位 128-bit 小端整数加 1，注意仅适用于进位时低位不为0的情况
		/// 如果需要通用的：
		/// var carry = Avx2.CompareEqual(v, Vector256.Create(-1L)); carry &amp;= vMinusUpper128Le;
		/// </summary>
		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public Vector256<T> AddUInt128Le01()
		{
			Vector256<long> v = nonce.AsInt64();

			Vector256<long> vMinusUpper128Le = Vector256.Create(0, 0, -1, 0);
			Vector256<long> carry = Avx2.CompareEqual(v, vMinusUpper128Le);
			carry = Avx2.ShiftLeftLogical128BitLane(carry, 8);

			v -= vMinusUpper128Le;
			return (v - carry).As<long, T>();
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public Vector256<T> AddUInt32Le01()
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
		public Vector512<T> AddUInt128Le4444()
		{
			Vector512<ulong> v = nonce.AsUInt64();
			Vector512<ulong> thr = Vector512.Create
			(
				ulong.MaxValue - 4UL, 0xFFFF_FFFF_FFFF_FFFFUL,
				ulong.MaxValue - 4UL, 0xFFFF_FFFF_FFFF_FFFFUL,
				ulong.MaxValue - 4UL, 0xFFFF_FFFF_FFFF_FFFFUL,
				ulong.MaxValue - 4UL, 0xFFFF_FFFF_FFFF_FFFFUL
			);

			Vector512<ulong> sum = v + Vector512.Create(4, 0, 4, 0, 4, 0, 4, 0).AsUInt64();

			Vector512<ulong> carry = Vector512.GreaterThan(v, thr);
			carry = Avx512BW.ShiftLeftLogical128BitLane(carry.AsByte(), 8).AsUInt64();

			return (sum - carry).As<ulong, T>();
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public Vector512<T> AddUInt32Le4444()
		{
			return (nonce.AsUInt32() + Vector512.Create(4u, 0, 0, 0, 4u, 0, 0, 0, 4u, 0, 0, 0, 4u, 0, 0, 0)).As<uint, T>();
		}

		/// <summary>
		/// [v0,v1,v2,v3] => [v0+0,v1+1,v2+2,v3+3]
		/// </summary>
		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public Vector512<T> AddUInt128Le0123()
		{
			Vector512<ulong> v = nonce.AsUInt64();
			Vector512<ulong> thr = Vector512.Create
			(
				ulong.MaxValue - 0UL, 0xFFFF_FFFF_FFFF_FFFFUL,
				ulong.MaxValue - 1UL, 0xFFFF_FFFF_FFFF_FFFFUL,
				ulong.MaxValue - 2UL, 0xFFFF_FFFF_FFFF_FFFFUL,
				ulong.MaxValue - 3UL, 0xFFFF_FFFF_FFFF_FFFFUL
			);

			Vector512<ulong> sum = v + Vector512.Create(0, 0, 1, 0, 2, 0, 3, 0).AsUInt64();

			Vector512<ulong> carry = Vector512.GreaterThan(v, thr);
			carry = Avx512BW.ShiftLeftLogical128BitLane(carry.AsByte(), 8).AsUInt64();

			return (sum - carry).As<ulong, T>();
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public Vector512<T> AddUInt32Le0123()
		{
			return (nonce.AsUInt32() + Vector512.Create(0u, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0)).As<uint, T>();
		}
	}
}
