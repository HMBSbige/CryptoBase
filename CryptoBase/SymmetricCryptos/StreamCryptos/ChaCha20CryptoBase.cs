using System;

namespace CryptoBase.SymmetricCryptos.StreamCryptos
{
	public abstract class ChaCha20CryptoBase : SnuffleCrypto
	{
		protected ChaCha20CryptoBase(ReadOnlySpan<byte> key, ReadOnlySpan<byte> iv) : base(key, iv) { }
	}
}
