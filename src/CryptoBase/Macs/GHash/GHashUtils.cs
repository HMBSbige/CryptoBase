using CryptoBase.Abstractions;

namespace CryptoBase.Macs.GHash;

public static class GHashUtils
{
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static IMac Create(ReadOnlySpan<byte> key)
	{
		if (Sse2.IsSupported && Pclmulqdq.IsSupported)
		{
			return new GHashX86(key);
		}

		return new GHashSF(key);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static Vector128<byte> GfMultiply(in Vector128<byte> a, in Vector128<byte> b)
	{
		GfMultiply(a, b, out Vector128<uint> lo, out Vector128<uint> hi);
		return Reduce(lo, hi);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static void GfMultiply(in Vector128<byte> a, in Vector128<byte> b, out Vector128<uint> lo, out Vector128<uint> hi)
	{
		Vector128<uint> p00 = Pclmulqdq.CarrylessMultiply(a.AsUInt64(), b.AsUInt64(), 0x00).AsUInt32();
		Vector128<uint> p10 = Pclmulqdq.CarrylessMultiply(a.AsUInt64(), b.AsUInt64(), 0x10).AsUInt32();
		Vector128<uint> p01 = Pclmulqdq.CarrylessMultiply(a.AsUInt64(), b.AsUInt64(), 0x01).AsUInt32();
		Vector128<uint> p11 = Pclmulqdq.CarrylessMultiply(a.AsUInt64(), b.AsUInt64(), 0x11).AsUInt32();

		Vector128<uint> mid = p10 ^ p01;
		Vector128<uint> midLo = Sse2.ShiftLeftLogical128BitLane(mid, 8);
		Vector128<uint> midHi = Sse2.ShiftRightLogical128BitLane(mid, 8);

		lo = p00 ^ midLo;
		hi = p11 ^ midHi;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static Vector128<byte> Reduce(in Vector128<uint> lo, in Vector128<uint> hi)
	{
		Vector128<uint> tmp3 = lo;
		Vector128<uint> tmp6 = hi;

		Vector128<uint> tmp7 = tmp3 >>> 31;
		Vector128<uint> tmp8 = tmp6 >>> 31;
		tmp3 <<= 1;
		tmp6 <<= 1;
		Vector128<uint> tmp9 = Sse2.ShiftRightLogical128BitLane(tmp7, 12);
		tmp8 = Sse2.ShiftLeftLogical128BitLane(tmp8, 4);
		tmp7 = Sse2.ShiftLeftLogical128BitLane(tmp7, 4);
		tmp3 |= tmp7;
		tmp6 |= tmp8;
		tmp6 |= tmp9;

		tmp7 = tmp3 << 31;
		tmp8 = tmp3 << 30;
		tmp9 = tmp3 << 25;
		tmp7 ^= tmp8;
		tmp7 ^= tmp9;
		tmp8 = Sse2.ShiftRightLogical128BitLane(tmp7, 4);
		tmp7 = Sse2.ShiftLeftLogical128BitLane(tmp7, 12);
		tmp3 ^= tmp7;
		Vector128<uint> tmp2 = tmp3 >>> 1;
		Vector128<uint> tmp4 = tmp3 >>> 2;
		Vector128<uint> tmp5 = tmp3 >>> 7;
		tmp2 ^= tmp4;
		tmp2 ^= tmp5;
		tmp2 ^= tmp8;
		tmp3 ^= tmp2;
		tmp6 ^= tmp3;

		return tmp6.AsByte();
	}
}
