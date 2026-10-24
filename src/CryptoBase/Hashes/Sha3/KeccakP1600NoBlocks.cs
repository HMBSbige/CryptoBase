namespace CryptoBase.Hashes.Sha3;

internal readonly struct KeccakP1600NoBlocks : IKeccakP1600Blocks
{
	public static bool Absorbs => false;

	public static bool Squeezes => false;

	public static int RateInBytes => 0;
}
