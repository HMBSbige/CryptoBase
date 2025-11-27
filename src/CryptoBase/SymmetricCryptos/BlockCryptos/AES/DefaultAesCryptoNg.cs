using Aes = System.Security.Cryptography.Aes;

namespace CryptoBase.SymmetricCryptos.BlockCryptos.AES;

internal readonly struct DefaultAesCryptoNg : IBlock16Crypto<DefaultAesCryptoNg>
{
	private readonly Aes _aes;

	private DefaultAesCryptoNg(in ReadOnlySpan<byte> key)
	{
		_aes = Aes.Create();
		_aes.Key = key.ToArray();
	}

	public void Dispose()
	{
		_aes.Dispose();
	}

	public static bool IsSupported => true;

	public static DefaultAesCryptoNg Create(in ReadOnlySpan<byte> key)
	{
		return new DefaultAesCryptoNg(key);
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
