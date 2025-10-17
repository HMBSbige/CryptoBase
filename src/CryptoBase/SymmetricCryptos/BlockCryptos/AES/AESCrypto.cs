using CryptoBase.Abstractions.SymmetricCryptos;

namespace CryptoBase.SymmetricCryptos.BlockCryptos.AES;

public abstract class AESCrypto : BlockCryptoBase
{
	public override string Name => @"AES";

	public sealed override int BlockSize => 16;

	protected static ReadOnlySpan<byte> Rcon => [AESUtils.Rcon0, AESUtils.Rcon1, AESUtils.Rcon2, AESUtils.Rcon3, AESUtils.Rcon4, AESUtils.Rcon5, AESUtils.Rcon6, AESUtils.Rcon7, AESUtils.Rcon8, AESUtils.Rcon9, AESUtils.Rcon10];

	protected AESCrypto(ReadOnlySpan<byte> key)
	{
		if (key.Length is not 16 and not 24 and not 32)
		{
			throw new ArgumentException(@"Key length must be 16/24/32 bytes", nameof(key));
		}
	}
}
