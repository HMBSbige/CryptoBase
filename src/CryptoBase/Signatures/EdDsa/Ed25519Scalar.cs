using CryptoBase.EllipticCurves;

namespace CryptoBase.Signatures.EdDsa;

// Integers modulo L in the elements of Ed25519Order, which RFC 8032 encodes in little-endian bytes. An element holds the plain value unless its name says Montgomery. Nothing branches on or indexes by a value, except IsCanonical, which takes a public one.
internal static class Ed25519Scalar
{
	internal const int Length = 32;

	internal const int WideLength = 64;

	// R mod L, the Montgomery form of 1.
	private static ref readonly FieldElement<Ed25519Order> MontgomeryOne => ref Unsafe.As<ulong, FieldElement<Ed25519Order>>(ref MemoryMarshal.GetReference(Ed25519Order.MontgomeryOne));

	// h mod L for the 64 little-endian bytes of h = a + 2^256·b: Multiply takes a left operand that is not reduced, so a·(R mod L)·R⁻¹ ≡ a and b·R²·R⁻¹ ≡ b·2^256.
	internal static void ReduceWide(ReadOnlySpan<byte> source, out FieldElement<Ed25519Order> result)
	{
		Debug.Assert(source.Length is WideLength);

		Read(source.Slice(0, Length), out FieldElement<Ed25519Order> low);
		Read(source.Slice(Length), out FieldElement<Ed25519Order> high);
		FieldElement<Ed25519Order>.Multiply(in low, in MontgomeryOne, out low);
		FieldElement<Ed25519Order>.ToMontgomery(in high, out high);
		FieldElement<Ed25519Order>.Add(in low, in high, out result);
		low.ZeroMemory();
		high.ZeroMemory();
	}

	// The Montgomery form of a mod L for any 32 little-endian bytes a, by the same reasoning.
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
