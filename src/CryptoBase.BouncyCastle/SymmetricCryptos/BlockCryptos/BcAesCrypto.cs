using CryptoBase.Abstractions.SymmetricCryptos;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;

namespace CryptoBase.BouncyCastle.SymmetricCryptos.BlockCryptos;

public sealed class BcAesCrypto : BlockCrypto16
{
	public override string Name => @"AES";

	public override BlockCryptoHardwareAcceleration HardwareAcceleration
	{
		get
		{
			if (AesUtilities.IsHardwareAccelerated)
			{
				return BlockCryptoHardwareAcceleration.Block1 | BlockCryptoHardwareAcceleration.Block4;
			}

			return BlockCryptoHardwareAcceleration.Unknown;
		}
	}

	private readonly IBlockCipher _encryptionEngine;
	private readonly IBlockCipher _decryptionEngine;

	public BcAesCrypto(ReadOnlySpan<byte> key)
	{
		KeyParameter keyParameter = new(key);

		_encryptionEngine = AesUtilities.CreateEngine();
		_decryptionEngine = AesUtilities.CreateEngine();
		_encryptionEngine.Init(true, keyParameter);
		_decryptionEngine.Init(false, keyParameter);
	}

	public override void Encrypt(ReadOnlySpan<byte> source, Span<byte> destination)
	{
		_encryptionEngine.ProcessBlock(source, destination);
	}

	public override void Decrypt(ReadOnlySpan<byte> source, Span<byte> destination)
	{
		_decryptionEngine.ProcessBlock(source, destination);
	}

	public override void Encrypt4(ReadOnlySpan<byte> source, Span<byte> destination)
	{
		if (_encryptionEngine is AesEngine_X86 engineX86)
		{
			engineX86.ProcessFourBlocks(source, destination);
		}
		else
		{
			base.Encrypt4(source, destination);
		}
	}

	public override void Decrypt4(ReadOnlySpan<byte> source, Span<byte> destination)
	{
		if (_decryptionEngine is AesEngine_X86 engineX86)
		{
			engineX86.ProcessFourBlocks(source, destination);
		}
		else
		{
			base.Decrypt4(source, destination);
		}
	}
}
