using Aes = System.Security.Cryptography.Aes;

namespace CryptoBase.SymmetricCryptos.BlockCryptos.AES;

internal readonly struct DefaultAesCipher : IBlock16Cipher<DefaultAesCipher>
{
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
}
