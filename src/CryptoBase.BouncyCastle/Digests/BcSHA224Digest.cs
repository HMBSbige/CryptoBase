using Org.BouncyCastle.Crypto.Digests;

namespace CryptoBase.BouncyCastle.Digests;

public sealed class BcSHA224Digest() : BcDigest(new Sha224Digest())
{
	public override string Name => @"SHA-224";
}
