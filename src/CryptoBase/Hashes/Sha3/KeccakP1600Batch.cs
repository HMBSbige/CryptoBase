namespace CryptoBase.Hashes.Sha3;

// Splits a batch of streams into groups for the interleaved kernels: the widest kernel takes groups while it can fill its lanes,
// and also the streams left over, except that a single stream goes to Times1 and two to four streams to Times4 rather than Times8.
internal static class KeccakP1600Batch
{
	internal static readonly int MaxLanes = ChooseMaxLanes();

	internal static int ChooseLanes(int streams)
	{
		Debug.Assert(streams > 0);

		if (streams >= MaxLanes)
		{
			return MaxLanes;
		}

		if (streams is 1)
		{
			return KeccakP1600Times1.Lanes;
		}

		// Up to four streams take Times4 even with Times8 at hand, which costs the same per call and moves twice the state.
		return streams <= KeccakP1600Times4.Lanes && MaxLanes > KeccakP1600Times4.Lanes ? KeccakP1600Times4.Lanes : MaxLanes;
	}

	internal static void Permute(int lanes, ref ulong state)
	{
		switch (lanes)
		{
			case 8:
			{
				KeccakP1600Times8.Permute(ref state);
				break;
			}
			case 4:
			{
				KeccakP1600Times4.Permute(ref state);
				break;
			}
			case 2:
			{
				KeccakP1600Times2.Permute(ref state);
				break;
			}
			default:
			{
				KeccakP1600Times1.Permute(ref state);
				break;
			}
		}
	}

	private static int ChooseMaxLanes()
	{
		if (KeccakP1600Times8.IsSupported)
		{
			return KeccakP1600Times8.Lanes;
		}

		if (KeccakP1600Times4.IsSupported)
		{
			return KeccakP1600Times4.Lanes;
		}

		return KeccakP1600Times2.IsSupported ? KeccakP1600Times2.Lanes : KeccakP1600Times1.Lanes;
	}
}
