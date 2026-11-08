namespace CryptoBase.EllipticCurves.SM9;

// G2, the subgroup of order N of E'(Fp2) for the twist E': y² = x³ + 5u, with the generator P2 of GM/T 0044.5 §3.1, for the protocols of GM/T 0044.2 to 0044.4. Points are affine, with reduced coordinates in Montgomery form, and never the point at infinity; scalars are plain values below N.
internal static class SM9G2
{
	// 04 ‖ x ‖ y with each coordinate a1 ‖ a0, the u-coefficient first, the uncompressed form of GM/T 0044.1 §7.2.8 with the field elements of §7.2.6.
	internal const int EncodedLength = 1 + 2 * SM9Fp2.ByteLength;

	internal static ref readonly SM9AffinePoint<SM9Fp2> Generator => ref SM9G2Group.Generator;

	// The form must be 04 ‖ x ‖ y with every coefficient below p, and the point on the twist and in G2, which E'(Fp2) does not fill. The checks branch on whether the encoding is valid alone, so the input may be a private key, whose coordinates in plain form are erased.
	[SkipLocalsInit]
	internal static bool TryDecode(ReadOnlySpan<byte> source, out SM9AffinePoint<SM9Fp2> result)
	{
		if (source.Length != EncodedLength || source[0] is not 0x04)
		{
			result = default;
			return false;
		}

		bool valid = SM9Fp2.TryImport(source.Slice(1, SM9Fp2.ByteLength), out SM9Fp2 x) & SM9Fp2.TryImport(source.Slice(1 + SM9Fp2.ByteLength), out SM9Fp2 y);
		SM9Fp2.ToMontgomery(in x, out result.X);
		SM9Fp2.ToMontgomery(in y, out result.Y);
		x.ZeroMemory();
		y.ZeroMemory();

		if (!valid || !SM9Curve<SM9Fp2>.IsOnCurve(in result) || !SM9G2Group.IsInSubgroupVariableTime(in result))
		{
			result = default;
			return false;
		}

		return true;
	}

	internal static void Encode(in SM9AffinePoint<SM9Fp2> point, Span<byte> destination)
	{
		Debug.Assert(destination.Length is EncodedLength);

		destination[0] = 0x04;
		SM9Fp2.ExportPlain(in point.X, destination.Slice(1, SM9Fp2.ByteLength));
		SM9Fp2.ExportPlain(in point.Y, destination.Slice(1 + SM9Fp2.ByteLength));
	}

	// k·P2 for k in [1, N − 1]; k = 0 gives (0, 0), not a point. Neither the time nor the addresses depend on k, and the projective product is erased.
	internal static void MultiplyBase(in FieldElement<SM9Order> scalar, out SM9AffinePoint<SM9Fp2> result)
	{
		SM9KernelDispatch.MultiplyBaseG2(in scalar, out SM9Point<SM9Fp2> product);
		_ = SM9Curve<SM9Fp2>.ToAffine(in product, out result);
		product.ZeroMemory();
	}

	// k·P2 + Q for a public k and Q of G2. Returns false, with result 0, if the sum is the point at infinity.
	internal static bool MultiplyBaseAddVariableTime(in FieldElement<SM9Order> scalar, in SM9AffinePoint<SM9Fp2> point, out SM9AffinePoint<SM9Fp2> result)
	{
		SM9Curve<SM9Fp2>.FromAffine(in point, out SM9Point<SM9Fp2> addend);
		SM9KernelDispatch.MultiplyBaseAddVariableTimeG2(in scalar, in addend, out SM9Point<SM9Fp2> sum);
		return SM9Curve<SM9Fp2>.ToAffineVariableTime(in sum, out result);
	}
}
