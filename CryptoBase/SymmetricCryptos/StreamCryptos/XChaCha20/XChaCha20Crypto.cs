using CryptoBase.SymmetricCryptos.StreamCryptos.ChaCha20Original;
using System;

namespace CryptoBase.SymmetricCryptos.StreamCryptos.XChaCha20
{
	public abstract class XChaCha20Crypto : ChaCha20OriginalCrypto
	{
		public override string Name => @"XChaCha20";

		public override int IvSize => 24;

		protected XChaCha20Crypto(byte[] key, byte[] iv) : base(key, iv) { }

		public abstract void SetIV(ReadOnlySpan<byte> iv);
		public abstract void SetCounter(uint counter);
	}
}
