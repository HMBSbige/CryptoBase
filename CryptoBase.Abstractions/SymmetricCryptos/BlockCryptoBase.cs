using System;

namespace CryptoBase.Abstractions.SymmetricCryptos
{
	public abstract class BlockCryptoBase : ISymmetricCrypto
	{
		public abstract string Name { get; }

		/// <summary>
		/// 用于加密/解密
		/// </summary>
		public abstract bool IsEncrypt { get; init; }

		/// <summary>
		/// 块大小，单位字节
		/// </summary>
		public abstract int BlockSize { get; }

		/// <summary>
		/// 处理一块
		/// </summary>
		public abstract void UpdateBlock(ReadOnlySpan<byte> source, Span<byte> destination);

		public virtual void Encrypt(ReadOnlySpan<byte> plain, Span<byte> cipher)
		{
			if (!IsEncrypt)
			{
				throw new InvalidOperationException();
			}

			UpdateBlock(plain, cipher);
		}

		public virtual void Decrypt(ReadOnlySpan<byte> cipher, Span<byte> plain)
		{
			if (IsEncrypt)
			{
				throw new InvalidOperationException();
			}

			UpdateBlock(cipher, plain);
		}

		public abstract void Reset();

		public virtual void Dispose() { }
	}
}
