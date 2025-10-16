using Org.BouncyCastle.Crypto.Digests;

namespace CryptoBase.BouncyCastle.Digests;

public sealed class BcSHA512Digest() : BcDigest(new Sha512Digest())
{
	public override string Name => @"SHA-512";
}
