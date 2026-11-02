using CryptoBase.EllipticCurves;
using static CryptoBase.EllipticCurves.LimbArithmetic;

namespace CryptoBase.Signatures.EdDsa;

// Integers modulo L in the elements of Ed25519Order, which RFC 8032 encodes in little-endian bytes. An element holds the plain value unless its name says Montgomery. Nothing branches on or indexes by a value, except IsCanonical, which takes a public one.
internal static class Ed25519Scalar
{
	internal const int Length = 32;

	internal const int WideLength = 64;

	// δ = L − 2^252, below 2^125.
	private const ulong Delta0 = 0x5812631A5CF5D3ED;
	private const ulong Delta1 = 0x14DEF9DEA2F79CD6;

	private const ulong Low60 = (1UL << 60) - 1;

	// 2^133·L = 2^385 + 2^133·δ and 2^7·L = 2^259 + 2^7·δ, the multiples of L that the first two folds of ReduceWide add.
	private static ReadOnlySpan<ulong> FirstMultiple => [0, 0, Delta0 << 5, Delta0 >> 59 | Delta1 << 5, Delta1 >> 59, 0, 2];

	private static ReadOnlySpan<ulong> SecondMultiple => [Delta0 << 7, Delta0 >> 57 | Delta1 << 7, Delta1 >> 57, 0, 8];

	// h mod L for the 64 little-endian bytes of h, by folds: as 2^252 ≡ −δ (mod L), a + 2^252·b ≡ a − δ·b, and a multiple of L at least δ·b keeps that positive. h < 2^512 gives b < 2^260 and δ·b < 2^385, so adding 2^133·L leaves the first remainder below 2^386; then b < 2^134, δ·b < 2^259, and 2^7·L leaves the second below 2^260; then b < 2^8, δ·b < 2^133 < L, and L leaves the third below 2^252 + L < 2L, which a conditional subtraction takes below L. Neither the time nor the addresses depend on h.
	[SkipLocalsInit]
	internal static void ReduceWide(ReadOnlySpan<byte> source, out FieldElement<Ed25519Order> result)
	{
		Debug.Assert(source.Length is WideLength);

		Span<ulong> remainder = stackalloc ulong[8];
		Span<ulong> high = stackalloc ulong[5];
		Span<ulong> product = stackalloc ulong[7];
		ref ulong r = ref MemoryMarshal.GetReference(remainder);
		ref ulong b = ref MemoryMarshal.GetReference(high);
		ref ulong p = ref MemoryMarshal.GetReference(product);

		for (int i = 0; i < remainder.Length; ++i)
		{
			Unsafe.Add(ref r, i) = BinaryPrimitives.ReadUInt64LittleEndian(source.Slice(i * sizeof(ulong)));
		}

		for (int i = 0; i < 5; ++i)
		{
			Unsafe.Add(ref b, i) = Unsafe.Add(ref r, i + 3) >> 60 | (i + 4 < remainder.Length ? Unsafe.Add(ref r, i + 4) << 4 : 0);
		}

		Unsafe.Add(ref r, 3) &= Low60;
		remainder.Slice(4).Clear();
		Fold(ref r, ref b, ref p, in MemoryMarshal.GetReference(FirstMultiple), 5);

		for (int i = 0; i < 3; ++i)
		{
			Unsafe.Add(ref b, i) = Unsafe.Add(ref r, i + 3) >> 60 | Unsafe.Add(ref r, i + 4) << 4;
		}

		Unsafe.Add(ref r, 3) &= Low60;
		remainder.Slice(4, 3).Clear();
		Fold(ref r, ref b, ref p, in MemoryMarshal.GetReference(SecondMultiple), 3);
		b = Unsafe.Add(ref r, 3) >> 60 | Unsafe.Add(ref r, 4) << 4;
		Unsafe.Add(ref r, 3) &= Low60;
		Unsafe.Add(ref r, 4) = 0;
		Fold(ref r, ref b, ref p, in MemoryMarshal.GetReference(Ed25519Order.Modulus), 1);

		// The third fold leaves the remainder below 2L.
		Unsafe.SkipInit(out result);
		ref ulong limbs = ref Unsafe.As<FieldElement<Ed25519Order>, ulong>(ref result);
		ulong borrow = SubtractLimbs(ref r, ref MemoryMarshal.GetReference(Ed25519Order.Modulus), ref limbs, 4);
		SelectLimbs(0 - borrow, ref r, ref limbs, ref limbs, 4);
		remainder.Clear();
		high.Clear();
		product.Clear();
	}

	// remainder + multiple − δ·b, for the count limbs of b that the caller has moved out of the remainder from bit 252 on, in max(count + 2, 4) limbs of remainder, which holds that sum; multiple is a multiple of L at least δ·b in as many limbs.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void Fold(ref ulong remainder, ref ulong b, ref ulong product, ref readonly ulong multiple, int count)
	{
		int length = Math.Max(count + 2, 4);
		Unsafe.Add(ref product, count) = MultiplyLimbs(ref b, Delta0, ref product, count);
		Unsafe.Add(ref product, count + 1) = MultiplyAddLimbs(ref b, Delta1, ref Unsafe.Add(ref product, 1), count);

		for (int i = count + 2; i < length; ++i)
		{
			Unsafe.Add(ref product, i) = 0;
		}

		AddLimbs(ref remainder, ref Unsafe.AsRef(in multiple), ulong.MaxValue, ref remainder, length);
		SubtractLimbs(ref remainder, ref product, ref remainder, length);
	}

	// The Montgomery form of a mod L for any 32 little-endian bytes a: ToMontgomery takes a left operand that is not reduced, and a·R²·R⁻¹ ≡ a·R.
	internal static void ToMontgomery(ReadOnlySpan<byte> source, out FieldElement<Ed25519Order> result)
	{
		Read(source, out FieldElement<Ed25519Order> value);
		FieldElement<Ed25519Order>.ToMontgomery(in value, out result);
		value.ZeroMemory();
	}

	// (r + k·s) mod L from s in Montgomery form, whose product with a plain k is plain.
	internal static void MultiplyAdd(in FieldElement<Ed25519Order> k, in FieldElement<Ed25519Order> montgomeryS, in FieldElement<Ed25519Order> r, out FieldElement<Ed25519Order> result)
	{
		FieldElement<Ed25519Order>.Multiply(in k, in montgomeryS, out FieldElement<Ed25519Order> product);
		FieldElement<Ed25519Order>.Add(in product, in r, out result);
		product.ZeroMemory();
	}

	internal static void Write(in FieldElement<Ed25519Order> value, Span<byte> destination)
	{
		Debug.Assert(destination.Length is Length);

		ReadOnlySpan<ulong> limbs = FieldElement<Ed25519Order>.GetLimbs(in value);
		BinaryPrimitives.WriteUInt64LittleEndian(destination, limbs[0]);
		BinaryPrimitives.WriteUInt64LittleEndian(destination.Slice(8), limbs[1]);
		BinaryPrimitives.WriteUInt64LittleEndian(destination.Slice(16), limbs[2]);
		BinaryPrimitives.WriteUInt64LittleEndian(destination.Slice(24), limbs[3]);
	}

	// Whether 32 little-endian bytes are below L, as the S of a signature must be. The time depends on the value.
	internal static bool IsCanonical(ReadOnlySpan<byte> source)
	{
		Debug.Assert(source.Length is Length);

		ReadOnlySpan<ulong> order = Ed25519Order.Modulus;

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

	// Any 32 little-endian bytes as they are, which may be L or more; only the left operand of Multiply and ToMontgomery takes such a value.
	private static void Read(ReadOnlySpan<byte> source, out FieldElement<Ed25519Order> result)
	{
		Debug.Assert(source.Length is Length);

		Unsafe.SkipInit(out result);
		ref ulong limbs = ref Unsafe.As<FieldElement<Ed25519Order>, ulong>(ref result);
		limbs = BinaryPrimitives.ReadUInt64LittleEndian(source);
		Unsafe.Add(ref limbs, 1) = BinaryPrimitives.ReadUInt64LittleEndian(source.Slice(8));
		Unsafe.Add(ref limbs, 2) = BinaryPrimitives.ReadUInt64LittleEndian(source.Slice(16));
		Unsafe.Add(ref limbs, 3) = BinaryPrimitives.ReadUInt64LittleEndian(source.Slice(24));
	}
}
