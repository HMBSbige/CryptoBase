namespace CryptoBase.Ciphers.Modes.Ctr;

internal static class CtrCounters<TIncrementer> where TIncrementer : struct, ICtrIncrementer
{
	private const int BlockSize = 16;

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static void Fill(ref Vector128<byte> counter, Span<byte> counters)
	{
		Debug.Assert(counters.Length % BlockSize is 0);

		Vector128<byte> current = counter.ReverseEndianness128();
		int i = 0;

		if (Avx512BW.IsSupported && counters.Length >= 64)
		{
			Vector512<byte> lanes = CtrLanes<TIncrementer>.Create4(current);

			for (; i <= counters.Length - 64; i += 64)
			{
				CtrLanes<TIncrementer>.Next4(ref lanes).StoreUnsafe(ref counters.GetReference(), (nuint)i);
			}

			current = lanes.GetLower().GetLower();
		}
		else if (Avx2.IsSupported && counters.Length >= 32)
		{
			Vector256<byte> lanes = CtrLanes<TIncrementer>.Create2(current);

			for (; i <= counters.Length - 32; i += 32)
			{
				CtrLanes<TIncrementer>.Next2(ref lanes).StoreUnsafe(ref counters.GetReference(), (nuint)i);
			}

			current = lanes.GetLower();
		}

		for (; i < counters.Length; i += BlockSize)
		{
			CtrLanes<TIncrementer>.Next(ref current).StoreUnsafe(ref counters.GetReference(), (nuint)i);
		}

		counter = current.ReverseEndianness128();
	}
}
