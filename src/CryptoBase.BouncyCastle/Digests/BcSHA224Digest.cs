using CryptoBase.Abstractions.Digests;
using Org.BouncyCastle.Crypto.Digests;

namespace CryptoBase.BouncyCastle.Digests;

public class BcSHA224Digest : BcDigest
{
	public override string Name => @"SHA-224";

	public override int Length => HashConstants.Sha224Length;

	public override int BlockSize => HashConstants.Sha224BlockSize;

	public BcSHA224Digest() : base(new Sha224Digest())
	{
	}
}
