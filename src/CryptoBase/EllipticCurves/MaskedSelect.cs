namespace CryptoBase.EllipticCurves;

// Every limb of every entry is read, so neither the time nor the addresses depend on the index.
internal static class MaskedSelect
{
	// result is zero if index ≥ count. Only hardware-accelerated vectors are used: the software fallback of the others may branch on the
	// values.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static void Lookup<T>(ref readonly T table, int count, uint index, out T result) where T : unmanaged
	{
		if (Vector512.IsHardwareAccelerated && Unsafe.SizeOf<T>() >= Vector512<byte>.Count)
		{
			Lookup<T, LimbVector512>(in table, count, index, out result);
		}
		else if (Vector256.IsHardwareAccelerated && Unsafe.SizeOf<T>() >= Vector256<byte>.Count)
		{
			Lookup<T, LimbVector256>(in table, count, index, out result);
		}
		else if (Vector128.IsHardwareAccelerated && Unsafe.SizeOf<T>() >= Vector128<byte>.Count)
		{
			Lookup<T, LimbVector128>(in table, count, index, out result);
		}
		else
		{
			Lookup<T, LimbScalar>(in table, count, index, out result);
		}
	}

	// If T is not a whole number of vectors, the last block overlaps the one before it; both write the same values to the shared limbs.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static void Lookup<T, TVector>(ref readonly T table, int count, uint index, out T result) where T : unmanaged where TVector : struct, ILimbVector<TVector>
	{
		int length = Unsafe.SizeOf<T>() / sizeof(ulong);

		Debug.Assert(Unsafe.SizeOf<T>() % sizeof(ulong) is 0 && length >= TVector.Count);

		ref ulong entries = ref Unsafe.As<T, ulong>(ref Unsafe.AsRef(in table));
		Unsafe.SkipInit(out result);
		ref ulong destination = ref Unsafe.As<T, ulong>(ref result);

		TVector target = TVector.Create(index);
		TVector one = TVector.Create(1);

		for (int block = 0; block < length; block += TVector.Count)
		{
			int offset = Math.Min(block, length - TVector.Count);
			ref ulong limbs = ref Unsafe.Add(ref entries, offset);
			TVector selected = TVector.Create(0);
			TVector position = selected;

			for (int j = 0; j < count; ++j)
			{
				selected |= TVector.Load(in limbs) & TVector.Equal(position, target);
				position += one;
				limbs = ref Unsafe.Add(ref limbs, length);
			}

			selected.Store(ref Unsafe.Add(ref destination, offset));
		}
	}
}
