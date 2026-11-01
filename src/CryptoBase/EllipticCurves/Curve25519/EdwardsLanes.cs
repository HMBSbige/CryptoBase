namespace CryptoBase.EllipticCurves.Curve25519;

// The parallel point formulas on the lanes of an IEdwardsField25519x4. A point is (X, Y, Z, T) in lanes A to D, reduced. A cached point, the right operand of a readdition, is (Y − X, Y + X, 2Z, 2dT) of a point up to a common factor, with lane D reduced or the negation of a reduced lane and the others reduced; a Niels point (y + x, y − x, 2dxy) caches as (y − x, y + x, 2, 2dxy).
// Each readdition and each doubling takes two products of the lanes, where the formulas of Edwards25519 take eight and seven of one element. A doubling gives extended coordinates whether an addition follows or not, as the lanes cost the same either way.
// The stack aligns locals to 16 bytes at most, and a vector that straddles a 64-byte line is read and written in two parts, which keeps its writes from forwarding to the reads of the next product; the callers keep every value in storage from Align.
internal static class EdwardsLanes
{
	internal const int Alignment = 64;

	// The bytes of storage for count values, with room to start them on a 64-byte line.
	internal static int StorageLength<TField>(int count) where TField : unmanaged, IEdwardsField25519x4<TField>
	{
		return count * Unsafe.SizeOf<TField>() + Alignment - 1;
	}

	// count values in storage of StorageLength(count) bytes, from its first 64-byte line.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static Span<TField> Align<TField>(Span<byte> storage, int count) where TField : unmanaged, IEdwardsField25519x4<TField>
	{
		return MemoryMarshal.Cast<byte, TField>(storage.Slice(AlignedOffset(storage), count * Unsafe.SizeOf<TField>()));
	}

	// The bytes of storage for an entry of a table, which AlignEntry starts on a 64-byte line, so that the vector stores of a lookup forward to the reads that follow them wherever the stack lies.
	internal static int EntryStorageLength => Unsafe.SizeOf<EdwardsNielsPoint>() + Alignment - 1;

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static ref EdwardsNielsPoint AlignEntry(Span<byte> storage)
	{
		return ref MemoryMarshal.AsRef<EdwardsNielsPoint>(storage.Slice(AlignedOffset(storage), Unsafe.SizeOf<EdwardsNielsPoint>()));
	}

	// The offset of the first 64-byte line in storage.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static unsafe int AlignedOffset(Span<byte> storage)
	{
		nint address = (nint)Unsafe.AsPointer(ref MemoryMarshal.GetReference(storage));
		return (int)(-address & Alignment - 1);
	}

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
