using CryptoBase.Abstractions.SymmetricCryptos;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;
using System;

namespace CryptoBase.SymmetricCryptos.StreamCryptos.RC4
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
			for (var i = 0; i < source.Length; ++i)
			{
				destination[i] = _rc4.ReturnByte(source[i]);
			}
		}

		public override void Reset()
		{
			_rc4.Reset();
		}
	}
}
