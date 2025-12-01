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

	public static BlockCryptoHardwareAcceleration HardwareAcceleration => BlockCryptoHardwareAcceleration.Unknown;

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

	[SkipLocalsInit]
	public VectorBuffer256 Encrypt(scoped in VectorBuffer256 source)
	{
		Unsafe.SkipInit(out VectorBuffer256 r);
		_aes.EncryptEcb(source, r, PaddingMode.None);
		return r;
	}

	[SkipLocalsInit]
	public VectorBuffer256 Decrypt(scoped in VectorBuffer256 source)
	{
		Unsafe.SkipInit(out VectorBuffer256 r);
		_aes.DecryptEcb(source, r, PaddingMode.None);
		return r;
	}

	[SkipLocalsInit]
	public VectorBuffer512 Encrypt(scoped in VectorBuffer512 source)
	{
		Unsafe.SkipInit(out VectorBuffer512 r);
		_aes.EncryptEcb(source, r, PaddingMode.None);
		return r;
	}

	[SkipLocalsInit]
	public VectorBuffer512 Decrypt(scoped in VectorBuffer512 source)
	{
		Unsafe.SkipInit(out VectorBuffer512 r);
		_aes.DecryptEcb(source, r, PaddingMode.None);
		return r;
	}
}
