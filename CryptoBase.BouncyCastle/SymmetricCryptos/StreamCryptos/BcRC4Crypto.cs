using CryptoBase.Abstractions.SymmetricCryptos;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;
using System;

namespace CryptoBase.BouncyCastle.SymmetricCryptos.StreamCryptos
{
	public class BcRC4Crypto : RC4CryptoBase
	{
		private readonly RC4Engine _rc4;

		public BcRC4Crypto(byte[] key) : base(key)
		{
			_rc4 = new RC4Engine();
			_rc4.Init(default, new KeyParameter(key));
		}

		protected override void Update(ReadOnlySpan<byte> source, Span<byte> destination)
		{
			_rc4.BcUpdateStream(source, destination);
		}

		public override void Reset()
		{
			_rc4.Reset();
		}
	}
}
