namespace CryptoBase.Macs.GHash;

public static class GHashUtils
{
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static IMac Create(ReadOnlySpan<byte> key)
	{
		if (GHashX86.IsSupported)
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

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static Vector256<byte> GfMultiply(in Vector256<byte> a, in Vector256<byte> b)
	{
		GfMultiply(a, b, out Vector256<uint> lo, out Vector256<uint> hi);
		return Reduce(lo, hi);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static void GfMultiply(in Vector256<byte> a, in Vector256<byte> b, out Vector256<uint> lo, out Vector256<uint> hi)
	{
		Vector256<uint> p10 = Pclmulqdq.V256.CarrylessMultiply(a.AsUInt64(), b.AsUInt64(), 0x10).AsUInt32();
		Vector256<uint> p01 = Pclmulqdq.V256.CarrylessMultiply(a.AsUInt64(), b.AsUInt64(), 0x01).AsUInt32();

		Vector256<uint> p00 = Pclmulqdq.V256.CarrylessMultiply(a.AsUInt64(), b.AsUInt64(), 0x00).AsUInt32();
		Vector256<uint> p11 = Pclmulqdq.V256.CarrylessMultiply(a.AsUInt64(), b.AsUInt64(), 0x11).AsUInt32();

		Vector256<uint> mid = p10 ^ p01;
		Vector256<uint> midLo = Avx2.ShiftLeftLogical128BitLane(mid, 8);
		Vector256<uint> midHi = Avx2.ShiftRightLogical128BitLane(mid, 8);

		lo = p00 ^ midLo;
		hi = p11 ^ midHi;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static Vector256<byte> Reduce(in Vector256<uint> lo, in Vector256<uint> hi)
	{
		Vector256<uint> carryLo = lo >>> 31;
		Vector256<uint> carryHi = hi >>> 31;

		Vector256<uint> loShifted1 = lo << 1;
		Vector256<uint> hiShifted1 = hi << 1;

		Vector256<uint> carryIntoLo = Avx2.ShiftLeftLogical128BitLane(carryLo.AsByte(), 4).AsUInt32();
		Vector256<uint> carryIntoHiSelf = Avx2.ShiftLeftLogical128BitLane(carryHi.AsByte(), 4).AsUInt32();
		Vector256<uint> carryFromLoToHi = Avx2.ShiftRightLogical128BitLane(carryLo.AsByte(), 12).AsUInt32();

		Vector256<uint> loMerged = loShifted1 | carryIntoLo;
		Vector256<uint> hiMerged = hiShifted1 | carryIntoHiSelf | carryFromLoToHi;

		Vector256<uint> xL31 = loMerged << 31;
		Vector256<uint> xL30 = loMerged << 30;
		Vector256<uint> xL25 = loMerged << 25;

		Vector256<uint> polyHi = xL31 ^ xL30 ^ xL25;

		Vector256<uint> polyToLo = Avx2.ShiftLeftLogical128BitLane(polyHi.AsByte(), 12).AsUInt32();
		Vector256<uint> polyToHi = Avx2.ShiftRightLogical128BitLane(polyHi.AsByte(), 4).AsUInt32();

		Vector256<uint> x = loMerged ^ polyToLo;

		Vector256<uint> xR1 = x >>> 1;
		Vector256<uint> xR2 = x >>> 2;
		Vector256<uint> xR7 = x >>> 7;

		Vector256<uint> foldA = xR1 ^ xR2;
		Vector256<uint> foldB = xR7 ^ polyToHi;

		Vector256<uint> loReduced = x ^ foldA ^ foldB;

		return (hiMerged ^ loReduced).AsByte();
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static Vector128<byte> ReduceTo128(in Vector256<uint> lo, in Vector256<uint> hi)
	{
		return Reduce(lo.GetLower() ^ lo.GetUpper(), hi.GetLower() ^ hi.GetUpper());
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static Vector512<byte> GfMultiply(in Vector512<byte> a, in Vector512<byte> b)
	{
		GfMultiply(a, b, out Vector512<uint> lo, out Vector512<uint> hi);
		return Reduce(lo, hi);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static void GfMultiply(in Vector512<byte> a, in Vector512<byte> b, out Vector512<uint> lo, out Vector512<uint> hi)
	{
		Vector512<uint> p10 = Pclmulqdq.V512.CarrylessMultiply(a.AsUInt64(), b.AsUInt64(), 0x10).AsUInt32();
		Vector512<uint> p01 = Pclmulqdq.V512.CarrylessMultiply(a.AsUInt64(), b.AsUInt64(), 0x01).AsUInt32();

		Vector512<uint> p00 = Pclmulqdq.V512.CarrylessMultiply(a.AsUInt64(), b.AsUInt64(), 0x00).AsUInt32();
		Vector512<uint> p11 = Pclmulqdq.V512.CarrylessMultiply(a.AsUInt64(), b.AsUInt64(), 0x11).AsUInt32();

		Vector512<uint> mid = p10 ^ p01;
		Vector512<uint> midLo = Avx512BW.ShiftLeftLogical128BitLane(mid.AsByte(), 8).AsUInt32();
		Vector512<uint> midHi = Avx512BW.ShiftRightLogical128BitLane(mid.AsByte(), 8).AsUInt32();

		lo = p00 ^ midLo;
		hi = p11 ^ midHi;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static Vector128<byte> ReduceTo128(in Vector512<uint> lo, in Vector512<uint> hi)
	{
		ref Vector128<uint> loStart = ref Unsafe.As<Vector512<uint>, Vector128<uint>>(ref Unsafe.AsRef(in lo));
		ref Vector128<uint> hiStart = ref Unsafe.As<Vector512<uint>, Vector128<uint>>(ref Unsafe.AsRef(in hi));

		ref readonly Vector128<uint> lo0 = ref Unsafe.Add(ref loStart, 0);
		ref readonly Vector128<uint> lo1 = ref Unsafe.Add(ref loStart, 1);
		ref readonly Vector128<uint> lo2 = ref Unsafe.Add(ref loStart, 2);
		ref readonly Vector128<uint> lo3 = ref Unsafe.Add(ref loStart, 3);

		ref readonly Vector128<uint> hi0 = ref Unsafe.Add(ref hiStart, 0);
		ref readonly Vector128<uint> hi1 = ref Unsafe.Add(ref hiStart, 1);
		ref readonly Vector128<uint> hi2 = ref Unsafe.Add(ref hiStart, 2);
		ref readonly Vector128<uint> hi3 = ref Unsafe.Add(ref hiStart, 3);

		Vector128<uint> l = lo0 ^ lo1 ^ lo2 ^ lo3;
		Vector128<uint> h = hi0 ^ hi1 ^ hi2 ^ hi3;

		return Reduce(l, h);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static Vector512<byte> Reduce(in Vector512<uint> lo, in Vector512<uint> hi)
	{
		Vector512<uint> carryLo = lo >>> 31;
		Vector512<uint> carryHi = hi >>> 31;

		Vector512<uint> loShifted1 = lo << 1;
		Vector512<uint> hiShifted1 = hi << 1;

		Vector512<uint> carryIntoLo = Avx512BW.ShiftLeftLogical128BitLane(carryLo.AsByte(), 4).AsUInt32();
		Vector512<uint> carryIntoHiSelf = Avx512BW.ShiftLeftLogical128BitLane(carryHi.AsByte(), 4).AsUInt32();
		Vector512<uint> carryFromLoToHi = Avx512BW.ShiftRightLogical128BitLane(carryLo.AsByte(), 12).AsUInt32();

		Vector512<uint> loMerged = loShifted1 | carryIntoLo;
		Vector512<uint> hiMerged = hiShifted1 | carryIntoHiSelf | carryFromLoToHi;

		Vector512<uint> xL31 = loMerged << 31;
		Vector512<uint> xL30 = loMerged << 30;
		Vector512<uint> xL25 = loMerged << 25;

		Vector512<uint> polyHi = xL31 ^ xL30 ^ xL25;

		Vector512<uint> polyToLo = Avx512BW.ShiftLeftLogical128BitLane(polyHi.AsByte(), 12).AsUInt32();
		Vector512<uint> polyToHi = Avx512BW.ShiftRightLogical128BitLane(polyHi.AsByte(), 4).AsUInt32();

		Vector512<uint> x = loMerged ^ polyToLo;

		Vector512<uint> xR1 = x >>> 1;
		Vector512<uint> xR2 = x >>> 2;
		Vector512<uint> xR7 = x >>> 7;

		Vector512<uint> foldA = xR1 ^ xR2;
		Vector512<uint> foldB = xR7 ^ polyToHi;

		Vector512<uint> loReduced = x ^ foldA ^ foldB;

		return (hiMerged ^ loReduced).AsByte();
	}
}
