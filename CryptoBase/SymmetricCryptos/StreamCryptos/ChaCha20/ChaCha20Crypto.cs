using CryptoBase.SymmetricCryptos.StreamCryptos.ChaCha20Original;
using System;

namespace CryptoBase.SymmetricCryptos.StreamCryptos.ChaCha20
{
	public abstract class ChaCha20Crypto : ChaCha20OriginalCrypto
	{
		public override string Name => @"ChaCha20";

		public override int IvSize => 12;

		protected ChaCha20Crypto(byte[] key, byte[] iv) : base(key, iv) { }

		protected override unsafe void IncrementCounter(uint* state)
		{
			if (++*(state + 12) == 0)
			{
				throw new InvalidOperationException(@"Data maximum length reached.");
			}
		}
	}
}
