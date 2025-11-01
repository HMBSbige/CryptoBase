namespace CryptoBase.SymmetricCryptos.BlockCryptos.AES;

public abstract class AesCrypto : BlockCryptoBase
{
	public override string Name => @"AES";

	public sealed override int BlockSize => 16;

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

	protected AesCrypto(ReadOnlySpan<byte> key)
	{
		if (key.Length is not 16 and not 24 and not 32)
		{
			ThrowHelper.ThrowArgumentOutOfRangeException<int>(nameof(key), "Key length must be 16/24/32 bytes");
		}
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static AesCrypto CreateCore(ReadOnlySpan<byte> key)
	{
		if (AesX86.IsSupported && Sse2.IsSupported)
		{
			return key.Length switch
			{
				16 => new Aes128CryptoX86(key),
				24 => new Aes192CryptoX86(key),
				32 => new Aes256CryptoX86(key),
				_ => ThrowHelper.ThrowArgumentOutOfRangeException<AesCrypto>(nameof(key), "Key length must be 16/24/32 bytes")
			};
		}

		return new DefaultAesCrypto(key);
	}
}
