using CryptoBase.Abstractions;
using CryptoBase.Abstractions.SymmetricCryptos;
using System;

namespace CryptoBase.SymmetricCryptos.BlockCryptos.AES
{
	public abstract class AESCrypto : BlockCryptoBase, IIntrinsics
	{
		public abstract bool IsSupport { get; }

		public override string Name => @"AES";

		public override int BlockSize => 16;

		protected readonly ReadOnlyMemory<byte> Key;

		protected static ReadOnlySpan<byte> Rcon => new byte[]
		{
			0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
		};

		protected AESCrypto(byte[] key)
		{
			if (key.Length is not 16 and not 24 and not 32)
			{
				throw new ArgumentException(@"Key length must be 16/24/32 bytes", nameof(key));
			}

			Key = key;
		}

		protected abstract void Init();
	}
}
