using CryptoBase.Abstractions.SymmetricCryptos;
using CryptoBase.SymmetricCryptos.BlockCryptoModes;
using System.Security.Cryptography;
using Aes = System.Security.Cryptography.Aes;

namespace CryptoBase.SymmetricCryptos.BlockCryptos.AES;

public static class AESUtils
{
	public const byte Rcon0 = 0x00;
	public const byte Rcon1 = 0x01;
	public const byte Rcon2 = 0x02;
	public const byte Rcon3 = 0x04;
	public const byte Rcon4 = 0x08;
	public const byte Rcon5 = 0x10;
	public const byte Rcon6 = 0x20;
	public const byte Rcon7 = 0x40;
	public const byte Rcon8 = 0x80;
	public const byte Rcon9 = 0x1b;
	public const byte Rcon10 = 0x36;

	public static readonly Aes AesEcb;
	public static readonly Aes AesCbc;

	static AESUtils()
	{
		AesEcb = Aes.Create();
		AesEcb.Mode = CipherMode.ECB;
		AesEcb.Padding = PaddingMode.None;

		AesCbc = Aes.Create();
		AesCbc.Mode = CipherMode.CBC;
		AesCbc.Padding = PaddingMode.None;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static IBlockCrypto CreateECB(ReadOnlySpan<byte> key)
	{
		if (System.Runtime.Intrinsics.X86.Aes.IsSupported && Sse2.IsSupported)
		{
			return key.Length switch
			{
				16 => new Aes128CryptoX86(key),
				24 => new Aes192CryptoX86(key),
				32 => new Aes256CryptoX86(key),
				_ => throw new ArgumentOutOfRangeException(nameof(key))
			};
		}

		return new AESECBCrypto(key);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static IBlockCrypto CreateCBC(ReadOnlySpan<byte> key, ReadOnlySpan<byte> iv)
	{
		if (System.Runtime.Intrinsics.X86.Aes.IsSupported && Sse2.IsSupported)
		{
			return new CBCBlockMode(CreateECB(key), iv);
		}

		return new AESCBCCrypto(key, iv);
	}
}
