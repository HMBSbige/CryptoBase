namespace CryptoBase.Hashes.SM3;

// W[0..67] of the blocks of two groups of lanes, one vector to a word, as SM3Schedule holds them for one block: group 1 from vector 68 on. Past round 15, the rounds keep the working state of each group in its W[0..7].
[InlineArray(136)]
internal struct SM3LaneSchedule<TVector> where TVector : unmanaged
{
	private TVector t;
}
