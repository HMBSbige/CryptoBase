namespace CryptoBase.EllipticCurves.Curve25519;

// The parallel point formulas on the lanes of an IEdwardsField25519x4. A point is (X, Y, Z, T) in lanes A to D, reduced. A cached point, the right operand of a readdition, is (Y − X, Y + X, 2Z, 2dT) of a point up to a common factor, with lane D reduced or the negation of a reduced lane and the others reduced; a Niels point (y + x, y − x, 2dxy) caches as (y − x, y + x, 2, 2dxy).
// Each readdition and each doubling takes two products of the lanes, where the formulas of Edwards25519 take eight and seven of one element. A doubling gives extended coordinates whether an addition follows or not, as the lanes cost the same either way.
// The stack aligns locals to 16 bytes at most, and a vector that straddles a 64-byte line is read and written in two parts, which keeps its writes from forwarding to the reads of the next product; the callers keep every value in storage from AlignedScratch.Align.
internal static class EdwardsLanes
{
	// point + cached by way of (Y − X, Y + X, Z, T)·cached = (S8, S9, S10, S11), with left and right for the operands.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static void Add<TField>(ref TField point, in TField cached, ref TField left, ref TField right) where TField : unmanaged, IEdwardsField25519x4<TField>
	{
		TField.AddOperands(in point, in cached, out left, out right);
		TField.Multiply(in left, in right, out point);
	}

	// [2]point by way of (X², Y², Z², −(X + Y)²) = (S1, S2, S3, −S4).
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static void Double<TField>(ref TField point, ref TField left, ref TField right) where TField : unmanaged, IEdwardsField25519x4<TField>
	{
		TField.DoubleOperands(in point, out left, out right);
		TField.Multiply(in left, in right, out point);
	}
}
