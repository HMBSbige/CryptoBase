namespace CryptoBase.Hashes.Sha3;

internal readonly struct KeccakP1600SqueezeBlocks<TRate> : IKeccakP1600Blocks where TRate : IKeccakRate
{
	public static bool Absorbs => false;

	public static bool Squeezes => true;

	public static int RateInBytes => TRate.RateInBytes;
}
