using CryptoBase.Abstractions.SymmetricCryptos;

namespace CryptoBase.SymmetricCryptos.BlockCryptos.AES;

public abstract class AESCrypto : BlockCryptoBase
{
	public override string Name => @"AES";

	public sealed override int BlockSize => 16;

	protected static ReadOnlySpan<byte> Rcon => new[]
	{
		Rcon0, Rcon1, Rcon2, Rcon3, Rcon4, Rcon5, Rcon6, Rcon7, Rcon8, Rcon9, Rcon10
	};

	protected const byte Rcon0 = 0x00;
	protected const byte Rcon1 = 0x01;
	protected const byte Rcon2 = 0x02;
	protected const byte Rcon3 = 0x04;
	protected const byte Rcon4 = 0x08;
	protected const byte Rcon5 = 0x10;
	protected const byte Rcon6 = 0x20;
	protected const byte Rcon7 = 0x40;
	protected const byte Rcon8 = 0x80;
	protected const byte Rcon9 = 0x1b;
	protected const byte Rcon10 = 0x36;

	protected AESCrypto(ReadOnlySpan<byte> key)
	{
		if (key.Length is not 16 and not 24 and not 32)
		{
			throw new ArgumentException(@"Key length must be 16/24/32 bytes", nameof(key));
		}
	}
}
