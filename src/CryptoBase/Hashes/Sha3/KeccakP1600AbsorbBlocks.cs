namespace CryptoBase.Hashes.Sha3;

internal readonly struct KeccakP1600AbsorbBlocks<TRate> : IKeccakP1600Blocks where TRate : IKeccakRate
{
	public static bool Absorbs => true;

	public static bool Squeezes => false;

	public static int RateInBytes => TRate.RateInBytes;
}
