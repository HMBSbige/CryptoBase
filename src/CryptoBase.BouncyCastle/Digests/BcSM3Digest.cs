using Org.BouncyCastle.Crypto.Digests;

namespace CryptoBase.BouncyCastle.Digests;

public sealed class BcSM3Digest() : BcDigest(new SM3Digest())
{
	public override string Name => @"SM3";
}
