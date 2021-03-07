using CryptoBase.Abstractions.Digests;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using System;

namespace CryptoBase.BouncyCastle.Digests
{
	public class BcMD5Digest : IHash
	{
		private readonly IDigest _hasher = new MD5Digest();

		public string Name => @"MD5";

		public int Length => HashConstants.Md5Length;

		public void UpdateFinal(ReadOnlySpan<byte> origin, Span<byte> destination)
		{
			_hasher.BcHashUpdateFinal(Length, origin, destination);
		}

		public void Update(ReadOnlySpan<byte> source)
		{
			_hasher.BcHashUpdate(source);
		}

		public void GetHash(Span<byte> destination)
		{
			_hasher.BcGetHash(Length, destination);
		}

		public void Reset()
		{
			_hasher.Reset();
		}
	}
}
