using CryptoBase.Abstractions.SymmetricCryptos;
using CryptoBase.BouncyCastle.Expansion;
using Org.BouncyCastle.Crypto.Parameters;
using System;

namespace CryptoBase.BouncyCastle.SymmetricCryptos.StreamCryptos
{
	public class BcXChaCha20Crypto : SnuffleCryptoBase
	{
		public override string Name => @"XChaCha20";

		public override int IvSize => 24;

		private readonly XChaCha20Engine _engine;

		public BcXChaCha20Crypto(byte[] key, byte[] iv) : base(key, iv)
		{
			_engine = new XChaCha20Engine();
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