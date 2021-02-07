using System;

namespace CryptoBase.Abstractions.SymmetricCryptos
{
	public interface IBlockCryptoMode
	{
		IBlockCrypto InternalBlockCrypto { get; init; }

		ReadOnlyMemory<byte> Iv { get; init; }
	}
}
