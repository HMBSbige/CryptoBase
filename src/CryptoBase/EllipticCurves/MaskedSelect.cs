namespace CryptoBase.EllipticCurves;

// Every limb of every entry is read, so neither the time nor the addresses depend on the index.
internal static class MaskedSelect
{
	// result is zero if index ≥ count. Only hardware-accelerated vectors are used: the software fallback of the others may branch on the values.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static void Lookup<T>(ref readonly T table, int count, uint index, out T result) where T : unmanaged
	{
		Unsafe.SkipInit(out result);
		Lookup(in Unsafe.As<T, ulong>(ref Unsafe.AsRef(in table)), Unsafe.SizeOf<T>() / sizeof(ulong), count, index, ref Unsafe.As<T, ulong>(ref result));
	}

	// As above for entries of length limbs.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static void Lookup(ref readonly ulong table, int length, int count, uint index, ref ulong result)
	{
		if (Vector512.IsHardwareAccelerated && length >= Vector512<ulong>.Count)
		{
			Lookup<LimbVector512>(in table, length, count, index, ref result);
		}
		else if (Vector256.IsHardwareAccelerated && length >= Vector256<ulong>.Count)
		{
			Lookup<LimbVector256>(in table, length, count, index, ref result);
		}
		else if (Vector128.IsHardwareAccelerated && length >= Vector128<ulong>.Count)
		{
			Lookup<LimbVector128>(in table, length, count, index, ref result);
		}
		else
		{
			Lookup<LimbScalar>(in table, length, count, index, ref result);
		}
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static void Lookup<T, TVector>(ref readonly T table, int count, uint index, out T result) where T : unmanaged where TVector : struct, ILimbVector<TVector>
	{
		Debug.Assert(Unsafe.SizeOf<T>() % sizeof(ulong) is 0);

		Unsafe.SkipInit(out result);
		Lookup<TVector>(in Unsafe.As<T, ulong>(ref Unsafe.AsRef(in table)), Unsafe.SizeOf<T>() / sizeof(ulong), count, index, ref Unsafe.As<T, ulong>(ref result));
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static void Lookup<TVector>(ref readonly ulong table, int length, int count, uint index, ref ulong result) where TVector : struct, ILimbVector<TVector>
	{
		Lookup(in table, length, count, TVector.Create(index), ref result);
	}

	// accumulator with value where mask is set. The accumulators start at zero and at most one entry of a window matches, so an OR merges as well as a select: ARM64 takes the select, one instruction there, and x64 the AND and the OR, where the select takes three.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static Vector128<ulong> Merge(Vector128<ulong> accumulator, Vector128<ulong> value, Vector128<ulong> mask)
	{
		return AdvSimd.IsSupported ? Vector128.ConditionalSelect(mask, value, accumulator) : accumulator | value & mask;
	}

	// As Lookup for entries that interleave two values: the limbs at even indices come from entry first, and the others from entry second. Only vectors of an even number of limbs are used, as they line up with the pairs.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static void LookupPair(ref readonly ulong table, int length, int count, uint first, uint second, ref ulong result)
	{
		Debug.Assert(length % 2 is 0 && Vector128.IsHardwareAccelerated);

		if (Vector512.IsHardwareAccelerated && length >= Vector512<ulong>.Count)
		{
			Lookup(in table, length, count, LimbVector512.Create(first, second), ref result);
		}
		else if (Vector256.IsHardwareAccelerated && length >= Vector256<ulong>.Count)
		{
			Lookup(in table, length, count, LimbVector256.Create(first, second), ref result);
		}
		else
		{
			Lookup(in table, length, count, LimbVector128.Create(first, second), ref result);
		}
	}

	// If an entry is not a whole number of vectors, the last block overlaps the one before it; both write the same values to the shared limbs. The even and the odd entries merge into accumulators of their own, which halves the chain of merges.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void Lookup<TVector>(ref readonly ulong table, int length, int count, TVector target, ref ulong result) where TVector : struct, ILimbVector<TVector>
	{
		Debug.Assert(length >= TVector.Count);

		ref ulong entries = ref Unsafe.AsRef(in table);
		TVector one = TVector.Create(1);
		TVector two = TVector.Create(2);

		for (int block = 0; block < length; block += TVector.Count)
		{
			int offset = Math.Min(block, length - TVector.Count);
			ref ulong limbs = ref Unsafe.Add(ref entries, offset);
			TVector even = TVector.Create(0);
			TVector odd = even;
			TVector position = even;
			TVector next = one;
			int j = 0;

			for (; j < count - 1; j += 2)
			{
				// Positions differ from entry to entry, so at most one entry matches, and its accumulator is still 0 there.
				even = TVector.MergeWhereEqual(even, position, target, in limbs);
				odd = TVector.MergeWhereEqual(odd, next, target, in Unsafe.Add(ref limbs, length));
				position += two;
				next += two;
				limbs = ref Unsafe.Add(ref limbs, 2 * length);
			}

			if (j < count)
			{
				even = TVector.MergeWhereEqual(even, position, target, in limbs);
			}

			(even | odd).Store(ref Unsafe.Add(ref result, offset));
		}
	}
}
