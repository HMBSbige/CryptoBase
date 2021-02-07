using System;

namespace CryptoBase.Abstractions.SymmetricCryptos
{
	public interface IStreamBlockCryptoMode : IStreamCrypto
	{
		public IBlockCrypto InternalBlockCrypto { get; init; }

		public ReadOnlyMemory<byte> Iv { get; init; }
	}
}
