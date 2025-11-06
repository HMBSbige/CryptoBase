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
		Vector128<ulong> aHi = Sse2.ShiftRightLogical128BitLane(a.AsUInt64(), 8);
		Vector128<ulong> bHi = Sse2.ShiftRightLogical128BitLane(b.AsUInt64(), 8);
		Vector128<ulong> aSum = a.AsUInt64() ^ aHi;
		Vector128<ulong> bSum = b.AsUInt64() ^ bHi;

		Vector128<uint> p00 = Pclmulqdq.CarrylessMultiply(a.AsUInt64(), b.AsUInt64(), 0x00).AsUInt32();
		Vector128<uint> p11 = Pclmulqdq.CarrylessMultiply(a.AsUInt64(), b.AsUInt64(), 0x11).AsUInt32();
		Vector128<uint> pm = Pclmulqdq.CarrylessMultiply(aSum, bSum, 0x00).AsUInt32();

		Vector128<uint> mid = pm ^ p00 ^ p11;

		Vector128<uint> midLo = Sse2.ShiftLeftLogical128BitLane(mid, 8);
		Vector128<uint> midHi = Sse2.ShiftRightLogical128BitLane(mid, 8);

		lo = p00 ^ midLo;
		hi = p11 ^ midHi;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static Vector128<byte> Reduce(in Vector128<uint> lo, in Vector128<uint> hi)
	{
		Vector128<uint> carryLo = lo >>> 31;
		Vector128<uint> carryHi = hi >>> 31;

		Vector128<uint> loShifted1 = lo << 1;
		Vector128<uint> hiShifted1 = hi << 1;

		Vector128<uint> carryIntoLo = Sse2.ShiftLeftLogical128BitLane(carryLo, 4);
		Vector128<uint> carryIntoHiSelf = Sse2.ShiftLeftLogical128BitLane(carryHi, 4);
		Vector128<uint> carryFromLoToHi = Sse2.ShiftRightLogical128BitLane(carryLo, 12);

		Vector128<uint> loMerged = loShifted1 | carryIntoLo;
		Vector128<uint> hiMerged = hiShifted1 | carryIntoHiSelf | carryFromLoToHi;

		Vector128<uint> xL31 = loMerged << 31;
		Vector128<uint> xL30 = loMerged << 30;
		Vector128<uint> xL25 = loMerged << 25;

		Vector128<uint> polyHi = xL31 ^ xL30 ^ xL25;

		Vector128<uint> polyToLo = Sse2.ShiftLeftLogical128BitLane(polyHi, 12);
		Vector128<uint> polyToHi = Sse2.ShiftRightLogical128BitLane(polyHi, 4);

		Vector128<uint> x = loMerged ^ polyToLo;

		Vector128<uint> xR1 = x >>> 1;
		Vector128<uint> xR2 = x >>> 2;
		Vector128<uint> xR7 = x >>> 7;

		Vector128<uint> foldA = xR1 ^ xR2;
		Vector128<uint> foldB = xR7 ^ polyToHi;

		Vector128<uint> loReduced = x ^ foldA ^ foldB;

		return (hiMerged ^ loReduced).AsByte();
	}
}
