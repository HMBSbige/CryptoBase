namespace CryptoBase.Ciphers.Modes.Gcm;

internal interface IGHashPowers
{
	void AppendPaddedSegment(ref Vector128<byte> accumulator, scoped ReadOnlySpan<byte> source, ref Vector128<byte> finalBlock);
}
