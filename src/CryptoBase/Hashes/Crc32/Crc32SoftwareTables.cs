namespace CryptoBase.Hashes.Crc32;

internal static class Crc32SoftwareTables
{
	internal const int TableSize = 256;
	internal const int FourWayBraidBlockSizeInBytes = 4 * sizeof(ulong);
	internal const int FiveWayBraidBlockSizeInBytes = 5 * sizeof(ulong);

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static ref Crc32TableSet Get<TAlgorithm>() where TAlgorithm : unmanaged
	{
		if (Crc32Engine.IsIeee<TAlgorithm>())
		{
			return ref Crc32IeeeTables.Tables;
		}

		return ref Crc32CastagnoliTables.Tables;
	}

	internal static void Initialize(uint polynomial, ref InlineArray256<uint> lookupBuffer, ref Crc32SlicingLookupBuffer slicingLookupBuffer, ref Crc32BraidLookupBuffer fourWayBraidLookupBuffer, ref Crc32BraidLookupBuffer fiveWayBraidLookupBuffer)
	{
		ref uint lookup = ref lookupBuffer[0];
		ref uint slicingLookup = ref slicingLookupBuffer[0];
		ref uint fourWayBraidLookup = ref fourWayBraidLookupBuffer[0];
		ref uint fiveWayBraidLookup = ref fiveWayBraidLookupBuffer[0];

		for (int i = 0; i < TableSize; ++i)
		{
			uint value = (uint)i;

			for (int bit = 0; bit < 8; ++bit)
			{
				value = (value & 1) is not 0 ? polynomial ^ value >> 1 : value >> 1;
			}

			Unsafe.Add(ref lookup, i) = value;
		}

		for (int i = 0; i < TableSize; ++i)
		{
			uint value = Unsafe.Add(ref lookup, i);

			for (int transition = 2; transition <= FiveWayBraidBlockSizeInBytes; ++transition)
			{
				value = Unsafe.Add(ref lookup, (byte)value) ^ value >> 8;

				if (transition is >= 2 and <= sizeof(ulong))
				{
					Unsafe.Add(ref slicingLookup, (transition - 2) * TableSize + i) = value;
				}

				if (transition is > FourWayBraidBlockSizeInBytes - sizeof(ulong) and <= FourWayBraidBlockSizeInBytes)
				{
					Unsafe.Add(ref fourWayBraidLookup, (FourWayBraidBlockSizeInBytes - transition) * TableSize + i) = value;
				}

				if (transition > FiveWayBraidBlockSizeInBytes - sizeof(ulong))
				{
					Unsafe.Add(ref fiveWayBraidLookup, (FiveWayBraidBlockSizeInBytes - transition) * TableSize + i) = value;
				}
			}
		}
	}
}
