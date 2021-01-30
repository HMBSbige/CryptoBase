using CryptoBase.Abstractions.SymmetricCryptos;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;
using System;

namespace CryptoBase.BouncyCastle.SymmetricCryptos.StreamCryptos
{
	public class BcSalsa20Crypto : SnuffleCryptoBase
	{
		public override string Name => @"Salsa20";

		private readonly Salsa20Engine _engine;

		public BcSalsa20Crypto(byte[] key, byte[] iv) : base(key, iv)
		{
			_engine = new Salsa20Engine();
			_engine.Init(default, new ParametersWithIV(new KeyParameter(key), iv));
		}

		public override void Update(ReadOnlySpan<byte> source, Span<byte> destination)
		{
			_engine.BcUpdateStream(source, destination);
		}

		public override void Reset()
		{
			_engine.Reset();
		}
	}
}
