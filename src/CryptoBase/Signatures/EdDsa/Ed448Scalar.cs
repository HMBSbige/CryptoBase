using CryptoBase.EllipticCurves;
using CryptoBase.EllipticCurves.Curve448;
using static CryptoBase.EllipticCurves.LimbArithmetic;

namespace CryptoBase.Signatures.EdDsa;

// Integers modulo L in the elements of Ed448Order, which RFC 8032 encodes in little-endian bytes. An element holds the plain value unless its name says Montgomery. Nothing branches on or indexes by a value, except IsCanonical, which takes a public one.
internal static class Ed448Scalar
{
	// The encoding of S (RFC 8032 §5.2.6): the 56 bytes of the value and a last byte of 0.
	internal const int Length = Edwards448.ScalarLength + 1;

	internal const int WideLength = 114;

	private const int LimbCount = 7;

	private const ulong Low62 = (1UL << 62) - 1;

	// δ = 2^446 − L, below 2^224, and 4δ = 2^448 mod L, below 2^226.
	private static ReadOnlySpan<ulong> Delta => [0xDC873D6D54A7BB0D, 0xDE933D8D723A70AA, 0x3BB124B65129C96F, 0x000000008335DC16];

	private static ReadOnlySpan<ulong> FourDelta => [0x721CF5B5529EEC34, 0x7A4CF635C8E9C2AB, 0xEEC492D944A725BF, 0x000000020CD77058];

	// h mod L for the 114 little-endian bytes of h, by folds: as 2^446 ≡ δ (mod L), a + 2^446·b ≡ a + δ·b and a + 2^448·b ≡ a + 4δ·b, which stay positive, so no multiple of L is added. h < 2^912 gives b = ⌊h/2^448⌋ < 2^464 and 4δ·b < 2^690, so the first remainder is below 2^691; then b < 2^243, 4δ·b < 2^469, and the second is below 2^470; then, from bit 446, b < 2^24, δ·b < 2^248, and the third is below 2^446 + 2^248 < 2L, which a conditional subtraction takes below L. Neither the time nor the addresses depend on h.
	[SkipLocalsInit]
	internal static void ReduceWide(ReadOnlySpan<byte> source, out FieldElement<Ed448Order> result)
	{
		Debug.Assert(source.Length is WideLength);

		Span<ulong> wide = stackalloc ulong[15];
		Span<ulong> remainder = stackalloc ulong[12];
		Span<ulong> product = stackalloc ulong[8];
		ref ulong h = ref MemoryMarshal.GetReference(wide);
		ref ulong r = ref MemoryMarshal.GetReference(remainder);
		ref ulong p = ref MemoryMarshal.GetReference(product);
		ref ulong fourDelta = ref MemoryMarshal.GetReference(FourDelta);

		for (int i = 0; i < 14; ++i)
		{
			Unsafe.Add(ref h, i) = BinaryPrimitives.ReadUInt64LittleEndian(source.Slice(i * sizeof(ulong)));
		}

		Unsafe.Add(ref h, 14) = BinaryPrimitives.ReadUInt16LittleEndian(source.Slice(14 * sizeof(ulong)));

		// The first fold: each row of b·4δ writes its carry to a limb no row has reached yet, so no carry ripples.
		wide.Slice(0, LimbCount).CopyTo(remainder);
		remainder.Slice(LimbCount).Clear();

		for (int i = 0; i < 4; ++i)
		{
			Unsafe.Add(ref r, i + 8) = MultiplyAddLimbs(ref Unsafe.Add(ref h, LimbCount), Unsafe.Add(ref fourDelta, i), ref Unsafe.Add(ref r, i), 8);
		}

		// The second multiplies b into its own buffer, as the rows would overwrite the remainder.
		Unsafe.Add(ref p, 4) = MultiplyLimbs(ref Unsafe.Add(ref r, LimbCount), fourDelta, ref p, 4);

		for (int i = 1; i < 4; ++i)
		{
			Unsafe.Add(ref p, i + 4) = MultiplyAddLimbs(ref Unsafe.Add(ref r, LimbCount), Unsafe.Add(ref fourDelta, i), ref Unsafe.Add(ref p, i), 4);
		}

		Unsafe.Add(ref r, LimbCount) = 0;
		AddLimbs(ref r, ref p, ulong.MaxValue, ref r, 8);

		// The third folds at 2^446.
		ulong b = Unsafe.Add(ref r, 6) >> 62 | Unsafe.Add(ref r, 7) << 2;
		Unsafe.Add(ref r, 6) &= Low62;
		Unsafe.Add(ref p, 4) = MultiplyLimbs(ref MemoryMarshal.GetReference(Delta), b, ref p, 4);
		product.Slice(5).Clear();
		AddLimbs(ref r, ref p, ulong.MaxValue, ref r, LimbCount);

		Unsafe.SkipInit(out result);
		ref ulong limbs = ref Unsafe.As<FieldElement<Ed448Order>, ulong>(ref result);
		ulong borrow = SubtractLimbs(ref r, ref MemoryMarshal.GetReference(Ed448Order.Modulus), ref limbs, LimbCount);
		SelectLimbs(0 - borrow, ref r, ref limbs, ref limbs, LimbCount);
		wide.Clear();
		remainder.Clear();
		product.Clear();
	}

	// The Montgomery form of a mod L for any 56 little-endian bytes a: ToMontgomery takes a left operand that is not reduced, and a·R²·R⁻¹ ≡ a·R.
	internal static void ToMontgomery(ReadOnlySpan<byte> source, out FieldElement<Ed448Order> result)
	{
		Read(source, out FieldElement<Ed448Order> value);
		FieldElement<Ed448Order>.ToMontgomery(in value, out result);
		value.ZeroMemory();
	}

	// (r + k·s) mod L from s in Montgomery form, whose product with a plain k is plain.
	internal static void MultiplyAdd(in FieldElement<Ed448Order> k, in FieldElement<Ed448Order> montgomeryS, in FieldElement<Ed448Order> r, out FieldElement<Ed448Order> result)
	{
		FieldElement<Ed448Order>.Multiply(in k, in montgomeryS, out FieldElement<Ed448Order> product);
		FieldElement<Ed448Order>.Add(in product, in r, out result);
		product.ZeroMemory();
	}

	// The 56 little-endian bytes of a value, the scalar that Edwards448 takes, or for a destination of Length bytes the encoding of RFC 8032, whose last byte is 0.
	internal static void Write(in FieldElement<Ed448Order> value, Span<byte> destination)
	{
		Debug.Assert(destination.Length is Edwards448.ScalarLength or Length);

		ReadOnlySpan<ulong> limbs = FieldElement<Ed448Order>.GetLimbs(in value);

		for (int i = 0; i < LimbCount; ++i)
		{
			BinaryPrimitives.WriteUInt64LittleEndian(destination.Slice(i * sizeof(ulong)), limbs[i]);
		}

		if (destination.Length is Length)
		{
			destination[Edwards448.ScalarLength] = 0;
		}
	}

	// Whether 57 little-endian bytes are below L, as the S of a signature must be: the last byte is 0, and the other 56 are below L. The time depends on the value.
	internal static bool IsCanonical(ReadOnlySpan<byte> source)
	{
		Debug.Assert(source.Length is Length);

		if (source[Edwards448.ScalarLength] is not 0)
		{
			return false;
		}

		ReadOnlySpan<ulong> order = Ed448Order.Modulus;

		for (int i = order.Length - 1; i >= 0; --i)
		{
			ulong limb = BinaryPrimitives.ReadUInt64LittleEndian(source.Slice(i * sizeof(ulong)));

			if (limb != order[i])
			{
				return limb < order[i];
			}
		}

		return false;
	}

	// Any 56 little-endian bytes as they are, which may be L or more; only the left operand of Multiply and ToMontgomery takes such a value.
	private static void Read(ReadOnlySpan<byte> source, out FieldElement<Ed448Order> result)
	{
		Debug.Assert(source.Length is Edwards448.ScalarLength);

		Unsafe.SkipInit(out result);
		ref ulong limbs = ref Unsafe.As<FieldElement<Ed448Order>, ulong>(ref result);

		for (int i = 0; i < LimbCount; ++i)
		{
			Unsafe.Add(ref limbs, i) = BinaryPrimitives.ReadUInt64LittleEndian(source.Slice(i * sizeof(ulong)));
		}
	}
}
