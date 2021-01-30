using CryptoBase.Abstractions.SymmetricCryptos;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;
using System;

namespace CryptoBase.BouncyCastle.SymmetricCryptos.StreamCryptos
{
	public class BcChaCha20Crypto : SnuffleCryptoBase
	{
		public override string Name => @"ChaCha20";

		public override int IvSize => 12;

		private readonly ChaCha7539Engine _engine;

		public BcChaCha20Crypto(byte[] key, byte[] iv) : base(key, iv)
		{
			_engine = new ChaCha7539Engine();
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
