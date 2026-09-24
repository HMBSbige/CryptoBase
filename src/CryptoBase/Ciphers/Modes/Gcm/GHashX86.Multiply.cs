namespace CryptoBase.Ciphers.Modes.Gcm;

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
		Vector128<uint> lowWordCarries = lo >>> 31;
		Vector128<uint> highWordCarries = hi >>> 31;
		Vector128<uint> shiftedLow = lo << 1;
		Vector128<uint> shiftedHigh = hi << 1;
		Vector128<uint> lowCarry = Sse2.ShiftLeftLogical128BitLane(lowWordCarries, 4);
		Vector128<uint> highCarry = Sse2.ShiftRightLogical128BitLane(lowWordCarries, 12);
		Vector128<uint> doubledLow = shiftedLow | lowCarry;
		Vector128<uint> doubledHigh = shiftedHigh | Sse2.ShiftLeftLogical128BitLane(highWordCarries, 4) | highCarry;

		Vector128<uint> shift30 = doubledLow << 30;
		Vector128<uint> shift25 = doubledLow << 25;
		Vector128<uint> polynomialOverflow = doubledLow << 31 ^ shift30 ^ shift25;
		Vector128<uint> polynomialLow = Sse2.ShiftLeftLogical128BitLane(polynomialOverflow, 12);
		Vector128<uint> polynomialHigh = Sse2.ShiftRightLogical128BitLane(polynomialOverflow, 4);

		Vector128<uint> foldedLow = doubledLow ^ polynomialLow;
		Vector128<uint> reducedLow = foldedLow ^ (foldedLow >>> 1 ^ foldedLow >>> 2) ^ (foldedLow >>> 7 ^ polynomialHigh);
		return (doubledHigh ^ reducedLow).AsByte();
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
		return product ^ key.AsUInt32().RotateWordsLeft(2).AsByte();
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static Vector256<byte> GetReductionKey(Vector256<byte> key)
	{
		Vector256<byte> polynomial = Vector256.Create(ReflectedPolynomial);
		Vector256<byte> product = Pclmulqdq.V256.CarrylessMultiply(key.AsUInt64(), polynomial.AsUInt64(), 0x10).AsByte();
		return product ^ Avx2.Shuffle(key.AsUInt32(), 0b01_00_11_10).AsByte();
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
		return folded ^ hi ^ lo.AsUInt32().RotateWordsLeft(2).AsByte();
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector256<byte> ReducePrepared(Vector256<byte> lo, Vector256<byte> hi)
	{
		Vector256<byte> polynomial = Vector256.Create(ReflectedPolynomial);
		Vector256<byte> folded = Pclmulqdq.V256.CarrylessMultiply(lo.AsUInt64(), polynomial.AsUInt64(), 0x10).AsByte();
		return folded ^ hi ^ Avx2.Shuffle(lo.AsUInt32(), 0b01_00_11_10).AsByte();
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
		Vector256<uint> lowWordCarries = lo >>> 31;
		Vector256<uint> highWordCarries = hi >>> 31;
		Vector256<uint> shiftedLow = lo << 1;
		Vector256<uint> shiftedHigh = hi << 1;
		Vector256<uint> lowCarry = Avx2.ShiftLeftLogical128BitLane(lowWordCarries, 4);
		Vector256<uint> highCarry = Avx2.ShiftRightLogical128BitLane(lowWordCarries, 12);
		Vector256<uint> doubledLow = shiftedLow | lowCarry;
		Vector256<uint> doubledHigh = shiftedHigh | Avx2.ShiftLeftLogical128BitLane(highWordCarries, 4) | highCarry;

		Vector256<uint> shift30 = doubledLow << 30;
		Vector256<uint> shift25 = doubledLow << 25;
		Vector256<uint> polynomialOverflow = doubledLow << 31 ^ shift30 ^ shift25;
		Vector256<uint> polynomialLow = Avx2.ShiftLeftLogical128BitLane(polynomialOverflow, 12);
		Vector256<uint> polynomialHigh = Avx2.ShiftRightLogical128BitLane(polynomialOverflow, 4);

		Vector256<uint> foldedLow = doubledLow ^ polynomialLow;
		Vector256<uint> reducedLow = foldedLow ^ (foldedLow >>> 1 ^ foldedLow >>> 2) ^ (foldedLow >>> 7 ^ polynomialHigh);
		return (doubledHigh ^ reducedLow).AsByte();
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
		Vector512<uint> lowWordCarries = lo >>> 31;
		Vector512<uint> highWordCarries = hi >>> 31;
		Vector512<uint> shiftedLow = lo << 1;
		Vector512<uint> shiftedHigh = hi << 1;
		Vector512<uint> lowCarry = Avx512BW.ShiftLeftLogical128BitLane(lowWordCarries.AsByte(), 4).AsUInt32();
		Vector512<uint> highCarry = Avx512BW.ShiftRightLogical128BitLane(lowWordCarries.AsByte(), 12).AsUInt32();
		Vector512<uint> doubledLow = shiftedLow | lowCarry;
		Vector512<uint> doubledHigh = shiftedHigh | Avx512BW.ShiftLeftLogical128BitLane(highWordCarries.AsByte(), 4).AsUInt32() | highCarry;

		Vector512<uint> shift30 = doubledLow << 30;
		Vector512<uint> shift25 = doubledLow << 25;
		Vector512<uint> polynomialOverflow = doubledLow << 31 ^ shift30 ^ shift25;
		Vector512<uint> polynomialLow = Avx512BW.ShiftLeftLogical128BitLane(polynomialOverflow.AsByte(), 12).AsUInt32();
		Vector512<uint> polynomialHigh = Avx512BW.ShiftRightLogical128BitLane(polynomialOverflow.AsByte(), 4).AsUInt32();

		Vector512<uint> foldedLow = doubledLow ^ polynomialLow;
		Vector512<uint> reducedLow = foldedLow ^ (foldedLow >>> 1 ^ foldedLow >>> 2) ^ (foldedLow >>> 7 ^ polynomialHigh);
		return (doubledHigh ^ reducedLow).AsByte();
	}
}
