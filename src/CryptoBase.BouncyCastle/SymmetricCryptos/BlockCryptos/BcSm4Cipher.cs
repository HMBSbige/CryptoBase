using CryptoBase.Abstractions.SymmetricCryptos;
using CryptoBase.Abstractions.Vectors;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;
using System.Runtime.CompilerServices;

namespace CryptoBase.BouncyCastle.SymmetricCryptos.BlockCryptos;

public sealed class BcSm4Cipher : IBlock16Cipher<BcSm4Cipher>
{
	public string Name => @"SM4";

	private readonly SM4Engine _encryptionEngine;

	private readonly SM4Engine _decryptionEngine;

	public void Dispose()
	{
	}

	public static bool IsSupported => true;

	public static BlockCipherHardwareAcceleration HardwareAcceleration => BlockCipherHardwareAcceleration.Unknown;

	private BcSm4Cipher(in ReadOnlySpan<byte> key)
	{
		KeyParameter keyParameter = new(key);

		_encryptionEngine = new SM4Engine();
		_decryptionEngine = new SM4Engine();
		_encryptionEngine.Init(true, keyParameter);
		_decryptionEngine.Init(false, keyParameter);
	}

	public static BcSm4Cipher Create(in ReadOnlySpan<byte> key)
	{
		return new BcSm4Cipher(key);
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

		r.Lower = Encrypt(source.Lower);
		r.Upper = Encrypt(source.Upper);

		return r;
	}

	public VectorBuffer64 Decrypt(scoped in VectorBuffer64 source)
	{
		Unsafe.SkipInit(out VectorBuffer64 r);

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

	public VectorBuffer128 EncryptV256(scoped in VectorBuffer128 source)
	{
		throw new NotSupportedException();
	}

	public VectorBuffer128 DecryptV256(scoped in VectorBuffer128 source)
	{
		throw new NotSupportedException();
	}

	public VectorBuffer256 EncryptV256(scoped in VectorBuffer256 source)
	{
		throw new NotSupportedException();
	}

	public VectorBuffer256 DecryptV256(scoped in VectorBuffer256 source)
	{
		throw new NotSupportedException();
	}

	public VectorBuffer256 EncryptV512(scoped in VectorBuffer256 source)
	{
		throw new NotSupportedException();
	}

	public VectorBuffer256 DecryptV512(scoped in VectorBuffer256 source)
	{
		throw new NotSupportedException();
	}

	public VectorBuffer512 EncryptV512(scoped in VectorBuffer512 source)
	{
		throw new NotSupportedException();
	}

	public VectorBuffer512 DecryptV512(scoped in VectorBuffer512 source)
	{
		throw new NotSupportedException();
	}
}
