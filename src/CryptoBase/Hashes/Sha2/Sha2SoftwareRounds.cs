namespace CryptoBase.Hashes.Sha2;

internal static class Sha2SoftwareRounds
{
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static void CompressEightRounds<TWord, TRounds>(ref TWord a, ref TWord b, ref TWord c, ref TWord d, ref TWord e, ref TWord f, ref TWord g, ref TWord h, ref TWord schedule, ref TWord roundConstants, int round, bool expand) where TRounds : struct, ISha2SoftwareRounds<TWord>
	{
		TRounds.CompressSoftwareRound(ref a, ref b, ref c, ref d, ref e, ref f, ref g, ref h, TRounds.RoundInput(ref schedule, ref roundConstants, round, expand));
		TRounds.CompressSoftwareRound(ref h, ref a, ref b, ref c, ref d, ref e, ref f, ref g, TRounds.RoundInput(ref schedule, ref roundConstants, round + 1, expand));
		TRounds.CompressSoftwareRound(ref g, ref h, ref a, ref b, ref c, ref d, ref e, ref f, TRounds.RoundInput(ref schedule, ref roundConstants, round + 2, expand));
		TRounds.CompressSoftwareRound(ref f, ref g, ref h, ref a, ref b, ref c, ref d, ref e, TRounds.RoundInput(ref schedule, ref roundConstants, round + 3, expand));
		TRounds.CompressSoftwareRound(ref e, ref f, ref g, ref h, ref a, ref b, ref c, ref d, TRounds.RoundInput(ref schedule, ref roundConstants, round + 4, expand));
		TRounds.CompressSoftwareRound(ref d, ref e, ref f, ref g, ref h, ref a, ref b, ref c, TRounds.RoundInput(ref schedule, ref roundConstants, round + 5, expand));
		TRounds.CompressSoftwareRound(ref c, ref d, ref e, ref f, ref g, ref h, ref a, ref b, TRounds.RoundInput(ref schedule, ref roundConstants, round + 6, expand));
		TRounds.CompressSoftwareRound(ref b, ref c, ref d, ref e, ref f, ref g, ref h, ref a, TRounds.RoundInput(ref schedule, ref roundConstants, round + 7, expand));
	}
}
