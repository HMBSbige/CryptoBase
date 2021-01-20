using CryptoBase.Abstractions.SymmetricCryptos;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;
using System;

namespace CryptoBase.SymmetricCryptos.StreamCryptos.Salsa20
{
	public class BcSalsa20Crypto : Salsa20CryptoBase
	{
		private readonly Salsa20Engine _engine;

		public BcSalsa20Crypto(byte[] key, byte[] iv) : base(key, iv)
		{
			_engine = new Salsa20Engine();
			_engine.Init(default, new ParametersWithIV(new KeyParameter(key), iv));
		}

		protected override void Update(ReadOnlySpan<byte> source, Span<byte> destination)
		{
			for (var i = 0; i < source.Length; ++i)
			{
				destination[i] = _engine.ReturnByte(source[i]);
			}
		}

		public override void Reset()
		{
			_engine.Reset();
		}
	}
}
