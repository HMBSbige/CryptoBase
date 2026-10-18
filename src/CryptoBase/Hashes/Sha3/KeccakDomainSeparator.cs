namespace CryptoBase.Hashes.Sha3;

// The suffix bits appended to the message (FIPS 202, Sec. 6), little-endian within the byte, followed by the first bit of pad10*1 (Sec. 5.1).
internal static class KeccakDomainSeparator
{
	// M || 01
	internal const byte Sha3 = 0x06;

	// M || 1111
	internal const byte Shake = 0x1F;
}
