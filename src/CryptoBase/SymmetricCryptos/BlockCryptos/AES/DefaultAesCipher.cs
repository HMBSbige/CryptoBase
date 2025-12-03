using Aes = System.Security.Cryptography.Aes;

namespace CryptoBase.SymmetricCryptos.BlockCryptos.AES;

internal readonly struct DefaultAesCipher : IBlock16Cipher<DefaultAesCipher>
{
	public string Name => @"AES";

	private readonly Aes _aes;

	private DefaultAesCipher(in ReadOnlySpan<byte> key)
	{
		_aes = Aes.Create();
		_aes.Key = key.ToArray();
	}

	public void Dispose()
	{
		_aes.Dispose();
	}

	public static bool IsSupported => true;

	public static BlockCipherHardwareAcceleration HardwareAcceleration => BlockCipherHardwareAcceleration.Unknown;

	public static DefaultAesCipher Create(in ReadOnlySpan<byte> key)
	{
		return new DefaultAesCipher(key);
	}

	[SkipLocalsInit]
	public VectorBuffer16 Encrypt(scoped in VectorBuffer16 source)
	{
		Unsafe.SkipInit(out VectorBuffer16 r);
		_aes.EncryptEcb(source, r, PaddingMode.None);
		return r;
	}

	[SkipLocalsInit]
	public VectorBuffer16 Decrypt(scoped in VectorBuffer16 source)
	{
		Unsafe.SkipInit(out VectorBuffer16 r);
		_aes.DecryptEcb(source, r, PaddingMode.None);
		return r;
	}

	[SkipLocalsInit]
	public VectorBuffer32 Encrypt(scoped in VectorBuffer32 source)
	{
		Unsafe.SkipInit(out VectorBuffer32 r);
		_aes.EncryptEcb(source, r, PaddingMode.None);
		return r;
	}

	[SkipLocalsInit]
	public VectorBuffer32 Decrypt(scoped in VectorBuffer32 source)
	{
		Unsafe.SkipInit(out VectorBuffer32 r);
		_aes.DecryptEcb(source, r, PaddingMode.None);
		return r;
	}

	[SkipLocalsInit]
	public VectorBuffer64 Encrypt(scoped in VectorBuffer64 source)
	{
		Unsafe.SkipInit(out VectorBuffer64 r);
		_aes.EncryptEcb(source, r, PaddingMode.None);
		return r;
	}

	[SkipLocalsInit]
	public VectorBuffer64 Decrypt(scoped in VectorBuffer64 source)
	{
		Unsafe.SkipInit(out VectorBuffer64 r);
		_aes.DecryptEcb(source, r, PaddingMode.None);
		return r;
	}

	[SkipLocalsInit]
	public VectorBuffer128 Encrypt(scoped in VectorBuffer128 source)
	{
		Unsafe.SkipInit(out VectorBuffer128 r);
		_aes.EncryptEcb(source, r, PaddingMode.None);
		return r;
	}

	[SkipLocalsInit]
	public VectorBuffer128 Decrypt(scoped in VectorBuffer128 source)
	{
		Unsafe.SkipInit(out VectorBuffer128 r);
		_aes.DecryptEcb(source, r, PaddingMode.None);
		return r;
	}

	public VectorBuffer128 EncryptV256(scoped in VectorBuffer128 source)
	{
		ThrowHelper.ThrowNotSupported();
		return default;
	}

	public VectorBuffer128 DecryptV256(scoped in VectorBuffer128 source)
	{
		ThrowHelper.ThrowNotSupported();
		return default;
	}

	public VectorBuffer256 EncryptV256(scoped in VectorBuffer256 source)
	{
		ThrowHelper.ThrowNotSupported();
		return default;
	}

	public VectorBuffer256 DecryptV256(scoped in VectorBuffer256 source)
	{
		ThrowHelper.ThrowNotSupported();
		return default;
	}

	public VectorBuffer256 EncryptV512(scoped in VectorBuffer256 source)
	{
		ThrowHelper.ThrowNotSupported();
		return default;
	}

	public VectorBuffer256 DecryptV512(scoped in VectorBuffer256 source)
	{
		ThrowHelper.ThrowNotSupported();
		return default;
	}

	public VectorBuffer512 EncryptV512(scoped in VectorBuffer512 source)
	{
		ThrowHelper.ThrowNotSupported();
		return default;
	}

	public VectorBuffer512 DecryptV512(scoped in VectorBuffer512 source)
	{
		ThrowHelper.ThrowNotSupported();
		return default;
	}
}
