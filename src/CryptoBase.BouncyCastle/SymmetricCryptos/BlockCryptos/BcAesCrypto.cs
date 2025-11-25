using CryptoBase.Abstractions.SymmetricCryptos;
using CryptoBase.Abstractions.Vectors;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;
using System.Runtime.CompilerServices;

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

	public override VectorBuffer16 Encrypt(scoped in VectorBuffer16 source)
	{
		Unsafe.SkipInit(out VectorBuffer16 r);
		_encryptionEngine.ProcessBlock(source, r);

		return r;
	}

	public override VectorBuffer16 Decrypt(scoped in VectorBuffer16 source)
	{
		Unsafe.SkipInit(out VectorBuffer16 r);
		_decryptionEngine.ProcessBlock(source, r);

		return r;
	}

	public override VectorBuffer64 Encrypt(scoped in VectorBuffer64 source)
	{
		if (_encryptionEngine is AesEngine_X86 engineX86)
		{
			Unsafe.SkipInit(out VectorBuffer64 r);
			engineX86.ProcessFourBlocks(source, r);

			return r;
		}

		return base.Encrypt(source);
	}

	public override VectorBuffer64 Decrypt(scoped in VectorBuffer64 source)
	{
		if (_decryptionEngine is AesEngine_X86 engineX86)
		{
			Unsafe.SkipInit(out VectorBuffer64 r);
			engineX86.ProcessFourBlocks(source, r);

			return r;
		}

		return base.Decrypt(source);
	}
}
