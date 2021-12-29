using CryptoBase.Abstractions.Digests;
using System.Security.Cryptography;

namespace CryptoBase.Digests.SHA512;

public class DefaultSHA512Digest : DefaultDigest
{
	public override string Name => @"SHA-512";

	public override int BlockSize => HashConstants.Sha512BlockSize;

	public DefaultSHA512Digest() : base(HashAlgorithmName.SHA512)
	{
	}
}
