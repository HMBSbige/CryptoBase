using System;

namespace CryptoBase.Abstractions.SymmetricCryptos
{
	public interface IBlockCrypto
	{
		/// <summary>
		/// 用于加密/解密
		/// </summary>
		bool IsEncrypt { get; init; }

		/// <summary>
		/// 块大小，单位字节
		/// </summary>
		int BlockSize { get; }

		/// <summary>
		/// 处理一块
		/// </summary>
		void UpdateBlock(ReadOnlySpan<byte> source, Span<byte> destination);
	}
}
