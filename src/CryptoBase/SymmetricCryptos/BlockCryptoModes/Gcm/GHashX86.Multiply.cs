namespace CryptoBase.SymmetricCryptos.BlockCryptoModes.Gcm;

internal static partial class GHashX86
{
	private static readonly Vector128<byte> ReflectedPolynomial = Vector128.Create(1UL, 0xc200000000000000UL).AsByte();

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static Vector128<byte> GFMultiply(Vector128<byte> a, Vector128<byte> b)
	{
		GFMultiply(a, b, out Vector128<uint> lo, out Vector128<uint> hi);
		return Reduce(lo, hi);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static Vector128<byte> GFSquare(Vector128<byte> value)
	{
		Vector128<ulong> limbs = value.AsUInt64();
		Vector128<uint> lo = Pclmulqdq.CarrylessMultiply(limbs, limbs, 0x00).AsUInt32();
		Vector128<uint> hi = Pclmulqdq.CarrylessMultiply(limbs, limbs, 0x11).AsUInt32();
		return Reduce(lo, hi);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static void GetFirstFourPowers(Vector128<byte> key1, out Vector256<byte> key21, out Vector256<byte> key43)
	{
		Vector128<byte> key2 = GFSquare(key1);
		key21 = Vector256.Create(key2, key1);
		key43 = GFMultiply(Vector256.Create(key2), key21);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static void GFMultiply(Vector128<byte> a, Vector128<byte> b, out Vector128<uint> lo, out Vector128<uint> hi)
	{
		GFMultiplyUnreduced(a, b, out Vector128<uint> p00, out Vector128<uint> p11, out Vector128<uint> pm);
		AssembleProduct(p00, p11, pm, out lo, out hi);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static void GFMultiplyUnreduced(Vector128<byte> a, Vector128<byte> b, out Vector128<uint> p00, out Vector128<uint> p11, out Vector128<uint> pm)
	{
		Vector128<ulong> aHi = Sse2.ShiftRightLogical128BitLane(a.AsUInt64(), 8);
		Vector128<ulong> bHi = Sse2.ShiftRightLogical128BitLane(b.AsUInt64(), 8);
		Vector128<ulong> aSum = a.AsUInt64() ^ aHi;
		Vector128<ulong> bSum = b.AsUInt64() ^ bHi;

		p00 = Pclmulqdq.CarrylessMultiply(a.AsUInt64(), b.AsUInt64(), 0x00).AsUInt32();
		p11 = Pclmulqdq.CarrylessMultiply(a.AsUInt64(), b.AsUInt64(), 0x11).AsUInt32();
		pm = Pclmulqdq.CarrylessMultiply(aSum, bSum, 0x00).AsUInt32();
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static void AssembleProduct(Vector128<uint> p00, Vector128<uint> p11, Vector128<uint> pm, out Vector128<uint> lo, out Vector128<uint> hi)
	{
		Vector128<uint> mid = pm ^ p00 ^ p11;

		Vector128<uint> midLo = Sse2.ShiftLeftLogical128BitLane(mid, 8);
		Vector128<uint> midHi = Sse2.ShiftRightLogical128BitLane(mid, 8);

		lo = p00 ^ midLo;
		hi = p11 ^ midHi;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static Vector128<byte> Reduce(Vector128<uint> lo, Vector128<uint> hi)
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
	private static Vector256<byte> GFMultiply(Vector256<byte> a, Vector256<byte> b)
	{
		GFMultiply(a, b, out Vector256<uint> lo, out Vector256<uint> hi);
		return Reduce(lo, hi);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static Vector128<byte> PrepareKey(Vector128<byte> key)
	{
		Vector128<ulong> limbs = key.AsUInt64();
		ulong reductionMask = 0UL - (limbs.GetElement(1) >> 63);
		Vector128<ulong> carry = limbs >> 63;
		Vector128<ulong> shifted = limbs << 1 | Sse2.ShiftLeftLogical128BitLane(carry, 8);
		return shifted.AsByte() ^ ReflectedPolynomial & Vector128.Create(reductionMask).AsByte();
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static Vector128<byte> GetReductionKey(Vector128<byte> key)
	{
		Vector128<byte> product = Pclmulqdq.CarrylessMultiply(key.AsUInt64(), ReflectedPolynomial.AsUInt64(), 0x10).AsByte();
		return product ^ Vector128.Shuffle(key.AsUInt32(), Vector128.Create(2u, 3, 0, 1)).AsByte();
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static Vector256<byte> GetReductionKey(Vector256<byte> key)
	{
		Vector256<byte> polynomial = Vector256.Create(ReflectedPolynomial);
		Vector256<byte> product = Pclmulqdq.V256.CarrylessMultiply(key.AsUInt64(), polynomial.AsUInt64(), 0x10).AsByte();
		return product ^ Vector256.Shuffle(key.AsUInt32(), Vector256.Create(2u, 3, 0, 1, 6, 7, 4, 5)).AsByte();
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static Vector128<byte> GFMultiplyPrepared(Vector128<byte> value, Vector128<byte> key, Vector128<byte> reductionKey)
	{
		GFMultiplyPreparedUnreduced(value, key, reductionKey, out Vector128<byte> lo, out Vector128<byte> hi);
		return ReducePrepared(lo, hi);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static void GFMultiplyPreparedUnreduced(Vector128<byte> value, Vector128<byte> key, Vector128<byte> reductionKey, out Vector128<byte> lo, out Vector128<byte> hi)
	{
		Vector128<ulong> value64 = value.AsUInt64();
		lo = Pclmulqdq.CarrylessMultiply(value64, reductionKey.AsUInt64(), 0x00).AsByte() ^ Pclmulqdq.CarrylessMultiply(value64, key.AsUInt64(), 0x01).AsByte();
		hi = Pclmulqdq.CarrylessMultiply(value64, reductionKey.AsUInt64(), 0x10).AsByte() ^ Pclmulqdq.CarrylessMultiply(value64, key.AsUInt64(), 0x11).AsByte();
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static Vector256<byte> GFMultiplyPrepared(Vector256<byte> value, Vector256<byte> key, Vector256<byte> reductionKey)
	{
		GFMultiplyPreparedUnreduced(value, key, reductionKey, out Vector256<byte> lo, out Vector256<byte> hi);
		return ReducePrepared(lo, hi);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static void GFMultiplyPreparedUnreduced(Vector256<byte> value, Vector256<byte> key, Vector256<byte> reductionKey, out Vector256<byte> lo, out Vector256<byte> hi)
	{
		Vector256<ulong> value64 = value.AsUInt64();
		lo = Pclmulqdq.V256.CarrylessMultiply(value64, reductionKey.AsUInt64(), 0x00).AsByte() ^ Pclmulqdq.V256.CarrylessMultiply(value64, key.AsUInt64(), 0x01).AsByte();
		hi = Pclmulqdq.V256.CarrylessMultiply(value64, reductionKey.AsUInt64(), 0x10).AsByte() ^ Pclmulqdq.V256.CarrylessMultiply(value64, key.AsUInt64(), 0x11).AsByte();
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static Vector128<byte> ReducePrepared(Vector128<byte> lo, Vector128<byte> hi)
	{
		Vector128<byte> folded = Pclmulqdq.CarrylessMultiply(lo.AsUInt64(), ReflectedPolynomial.AsUInt64(), 0x10).AsByte();
		return folded ^ hi ^ Vector128.Shuffle(lo.AsUInt32(), Vector128.Create(2u, 3, 0, 1)).AsByte();
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector256<byte> ReducePrepared(Vector256<byte> lo, Vector256<byte> hi)
	{
		Vector256<byte> polynomial = Vector256.Create(ReflectedPolynomial);
		Vector256<byte> folded = Pclmulqdq.V256.CarrylessMultiply(lo.AsUInt64(), polynomial.AsUInt64(), 0x10).AsByte();
		return folded ^ hi ^ Vector256.Shuffle(lo.AsUInt32(), Vector256.Create(2u, 3, 0, 1, 6, 7, 4, 5)).AsByte();
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static Vector128<byte> ReducePreparedTo128(Vector256<byte> lo, Vector256<byte> hi)
	{
		return ReducePrepared(lo.GetLower() ^ lo.GetUpper(), hi.GetLower() ^ hi.GetUpper());
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void GFMultiply(Vector256<byte> a, Vector256<byte> b, out Vector256<uint> lo, out Vector256<uint> hi)
	{
		GFMultiplyUnreduced(a, b, out Vector256<uint> p00, out Vector256<uint> p11, out Vector256<uint> pm);
		AssembleProduct(p00, p11, pm, out lo, out hi);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static void GFMultiplyUnreduced(Vector256<byte> a, Vector256<byte> b, out Vector256<uint> p00, out Vector256<uint> p11, out Vector256<uint> pm)
	{
		Vector256<ulong> aHi = Avx2.ShiftRightLogical128BitLane(a.AsUInt64(), 8);
		Vector256<ulong> bHi = Avx2.ShiftRightLogical128BitLane(b.AsUInt64(), 8);
		Vector256<ulong> aSum = a.AsUInt64() ^ aHi;
		Vector256<ulong> bSum = b.AsUInt64() ^ bHi;
		p00 = Pclmulqdq.V256.CarrylessMultiply(a.AsUInt64(), b.AsUInt64(), 0x00).AsUInt32();
		p11 = Pclmulqdq.V256.CarrylessMultiply(a.AsUInt64(), b.AsUInt64(), 0x11).AsUInt32();
		pm = Pclmulqdq.V256.CarrylessMultiply(aSum, bSum, 0x00).AsUInt32();
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void AssembleProduct(Vector256<uint> p00, Vector256<uint> p11, Vector256<uint> pm, out Vector256<uint> lo, out Vector256<uint> hi)
	{
		Vector256<uint> mid = pm ^ p00 ^ p11;
		Vector256<uint> midLo = Avx2.ShiftLeftLogical128BitLane(mid, 8);
		Vector256<uint> midHi = Avx2.ShiftRightLogical128BitLane(mid, 8);

		lo = p00 ^ midLo;
		hi = p11 ^ midHi;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector256<byte> Reduce(Vector256<uint> lo, Vector256<uint> hi)
	{
		Vector256<uint> carryLo = lo >>> 31;
		Vector256<uint> carryHi = hi >>> 31;

		Vector256<uint> loShifted1 = lo << 1;
		Vector256<uint> hiShifted1 = hi << 1;

		Vector256<uint> carryIntoLo = Avx2.ShiftLeftLogical128BitLane(carryLo, 4);
		Vector256<uint> carryIntoHiSelf = Avx2.ShiftLeftLogical128BitLane(carryHi, 4);
		Vector256<uint> carryFromLoToHi = Avx2.ShiftRightLogical128BitLane(carryLo, 12);

		Vector256<uint> loMerged = loShifted1 | carryIntoLo;
		Vector256<uint> hiMerged = hiShifted1 | carryIntoHiSelf | carryFromLoToHi;

		Vector256<uint> xL31 = loMerged << 31;
		Vector256<uint> xL30 = loMerged << 30;
		Vector256<uint> xL25 = loMerged << 25;

		Vector256<uint> polyHi = xL31 ^ xL30 ^ xL25;

		Vector256<uint> polyToLo = Avx2.ShiftLeftLogical128BitLane(polyHi, 12);
		Vector256<uint> polyToHi = Avx2.ShiftRightLogical128BitLane(polyHi, 4);

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
	private static Vector128<byte> ReduceTo128(Vector256<uint> lo, Vector256<uint> hi)
	{
		return Reduce(lo.GetLower() ^ lo.GetUpper(), hi.GetLower() ^ hi.GetUpper());
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static Vector512<byte> GFMultiply(Vector512<byte> a, Vector512<byte> b)
	{
		GFMultiply(a, b, out Vector512<uint> lo, out Vector512<uint> hi);
		return Reduce(lo, hi);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static void GFMultiply(Vector512<byte> a, Vector512<byte> b, out Vector512<uint> lo, out Vector512<uint> hi)
	{
		Vector512<ulong> aHi = Avx512BW.ShiftRightLogical128BitLane(a, 8).AsUInt64();
		Vector512<ulong> bHi = Avx512BW.ShiftRightLogical128BitLane(b, 8).AsUInt64();
		Vector512<ulong> aSum = a.AsUInt64() ^ aHi;
		Vector512<ulong> bSum = b.AsUInt64() ^ bHi;
		Vector512<uint> p00 = Pclmulqdq.V512.CarrylessMultiply(a.AsUInt64(), b.AsUInt64(), 0x00).AsUInt32();
		Vector512<uint> p11 = Pclmulqdq.V512.CarrylessMultiply(a.AsUInt64(), b.AsUInt64(), 0x11).AsUInt32();
		Vector512<uint> pm = Pclmulqdq.V512.CarrylessMultiply(aSum, bSum, 0x00).AsUInt32();

		Vector512<uint> mid = pm ^ p00 ^ p11;
		Vector512<uint> midLo = Avx512BW.ShiftLeftLogical128BitLane(mid.AsByte(), 8).AsUInt32();
		Vector512<uint> midHi = Avx512BW.ShiftRightLogical128BitLane(mid.AsByte(), 8).AsUInt32();

		lo = p00 ^ midLo;
		hi = p11 ^ midHi;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static Vector128<byte> ReduceTo128(Vector512<uint> lo, Vector512<uint> hi)
	{
		Vector256<uint> foldedLo = lo.GetLower() ^ lo.GetUpper();
		Vector256<uint> foldedHi = hi.GetLower() ^ hi.GetUpper();
		return ReduceTo128(foldedLo, foldedHi);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector512<byte> Reduce(Vector512<uint> lo, Vector512<uint> hi)
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
