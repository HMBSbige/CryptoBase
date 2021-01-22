using CryptoBase.Abstractions.SymmetricCryptos;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;
using System;

namespace CryptoBase.SymmetricCryptos.StreamCryptos.XSalsa20
{
	public class BcXSalsa20Crypto : Salsa20CryptoBase
	{
		public override string Name { get; } = @"XSalsa20";

		public override int IvSize { get; } = 24;

		private readonly XSalsa20Engine _engine;

		public BcXSalsa20Crypto(byte[] key, byte[] iv) : base(key, iv)
		{
			_engine = new XSalsa20Engine();
			_engine.Init(default, new ParametersWithIV(new KeyParameter(key), iv));
		}

		protected override void Update(ReadOnlySpan<byte> source, Span<byte> destination)
		{
			_engine.BcUpdateStream(source, destination);
		}

		public override void Reset()
		{
			_engine.Reset();
		}
	}
}
