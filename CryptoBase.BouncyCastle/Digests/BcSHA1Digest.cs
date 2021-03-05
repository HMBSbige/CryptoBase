using CryptoBase.Abstractions.Digests;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using System;

namespace CryptoBase.BouncyCastle.Digests
{
	public class BcSHA1Digest : IHash
	{
		private readonly IDigest _hasher = new Sha1Digest();

		public string Name => @"SHA-1";

		public int Length => HashConstants.Sha1Length;

		public void UpdateFinal(in ReadOnlySpan<byte> origin, Span<byte> destination)
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

		public void Dispose()
		{
		}

		public void Reset()
		{
			_hasher.Reset();
		}
	}
}
