namespace CryptoBase.Hashes.Sha2;

internal interface ISha2SoftwareRounds<TWord>
{
	static abstract void CompressSoftwareRound(ref TWord a, ref TWord b, ref TWord c, ref TWord d, ref TWord e, ref TWord f, ref TWord g, ref TWord h, TWord roundInput);

	static abstract TWord RoundInput(ref TWord schedule, ref TWord roundConstants, int round, bool expand);
}
