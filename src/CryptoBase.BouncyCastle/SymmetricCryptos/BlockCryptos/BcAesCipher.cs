using CryptoBase.Abstractions.SymmetricCryptos;
using CryptoBase.Abstractions.Vectors;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;
using System.Runtime.CompilerServices;

namespace CryptoBase.BouncyCastle.SymmetricCryptos.BlockCryptos;

public sealed class BcAesCipher : IBlock16Cipher<BcAesCipher>
{
	public string Name => @"AES";

	private readonly IBlockCipher _encryptionEngine;
	private readonly IBlockCipher _decryptionEngine;

	public void Dispose()
	{
	}

	public static bool IsSupported => true;

	public static BlockCryptoHardwareAcceleration HardwareAcceleration
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

	private BcAesCipher(in ReadOnlySpan<byte> key)
	{
		KeyParameter keyParameter = new(key);

		_encryptionEngine = AesUtilities.CreateEngine();
		_decryptionEngine = AesUtilities.CreateEngine();
		_encryptionEngine.Init(true, keyParameter);
		_decryptionEngine.Init(false, keyParameter);
	}

	public static BcAesCipher Create(in ReadOnlySpan<byte> key)
	{
		return new BcAesCipher(key);
	}

	public VectorBuffer16 Encrypt(scoped in VectorBuffer16 source)
	{
		Unsafe.SkipInit(out VectorBuffer16 r);
		_encryptionEngine.ProcessBlock(source, r);

		return r;
	}

	public VectorBuffer16 Decrypt(scoped in VectorBuffer16 source)
	{
		Unsafe.SkipInit(out VectorBuffer16 r);
		_decryptionEngine.ProcessBlock(source, r);

		return r;
	}

	public VectorBuffer32 Encrypt(scoped in VectorBuffer32 source)
	{
		Unsafe.SkipInit(out VectorBuffer32 r);

		r.Lower = Encrypt(source.Lower);
		r.Upper = Encrypt(source.Upper);

		return r;
	}

	public VectorBuffer32 Decrypt(scoped in VectorBuffer32 source)
	{
		Unsafe.SkipInit(out VectorBuffer32 r);

		r.Lower = Decrypt(source.Lower);
		r.Upper = Decrypt(source.Upper);

		return r;
	}

	public VectorBuffer64 Encrypt(scoped in VectorBuffer64 source)
	{
		Unsafe.SkipInit(out VectorBuffer64 r);

		if (_encryptionEngine is AesEngine_X86 engineX86)
		{
			engineX86.ProcessFourBlocks(source, r);
			return r;
		}

		r.Lower = Encrypt(source.Lower);
		r.Upper = Encrypt(source.Upper);

		return r;
	}

	public VectorBuffer64 Decrypt(scoped in VectorBuffer64 source)
	{
		Unsafe.SkipInit(out VectorBuffer64 r);

		if (_decryptionEngine is AesEngine_X86 engineX86)
		{
			engineX86.ProcessFourBlocks(source, r);
			return r;
		}

		r.Lower = Decrypt(source.Lower);
		r.Upper = Decrypt(source.Upper);

		return r;
	}

	public VectorBuffer128 Encrypt(scoped in VectorBuffer128 source)
	{
		Unsafe.SkipInit(out VectorBuffer128 r);

		r.Lower = Encrypt(source.Lower);
		r.Upper = Encrypt(source.Upper);

		return r;
	}

	public VectorBuffer128 Decrypt(scoped in VectorBuffer128 source)
	{
		Unsafe.SkipInit(out VectorBuffer128 r);

		r.Lower = Decrypt(source.Lower);
		r.Upper = Decrypt(source.Upper);

		return r;
	}

	public VectorBuffer256 Encrypt(scoped in VectorBuffer256 source)
	{
		Unsafe.SkipInit(out VectorBuffer256 r);

		r.Lower = Encrypt(source.Lower);
		r.Upper = Encrypt(source.Upper);

		return r;
	}

	public VectorBuffer256 Decrypt(scoped in VectorBuffer256 source)
	{
		Unsafe.SkipInit(out VectorBuffer256 r);

		r.Lower = Decrypt(source.Lower);
		r.Upper = Decrypt(source.Upper);

		return r;
	}

	public VectorBuffer512 Encrypt(scoped in VectorBuffer512 source)
	{
		Unsafe.SkipInit(out VectorBuffer512 r);

		r.Lower = Encrypt(source.Lower);
		r.Upper = Encrypt(source.Upper);

		return r;
	}

	public VectorBuffer512 Decrypt(scoped in VectorBuffer512 source)
	{
		Unsafe.SkipInit(out VectorBuffer512 r);

		r.Lower = Decrypt(source.Lower);
		r.Upper = Decrypt(source.Upper);

		return r;
	}
}
