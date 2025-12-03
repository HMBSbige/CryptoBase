using Aes = System.Security.Cryptography.Aes;

namespace CryptoBase.SymmetricCryptos.BlockCryptos.AES;

internal readonly struct DefaultAesCipher : IBlock16Cipher<DefaultAesCipher>
{
	public string Name => @"AES";

	private readonly Aes _aes;
	private readonly ICryptoTransform _encryptor;
	private readonly ICryptoTransform _decryptor;

	private DefaultAesCipher(in ReadOnlySpan<byte> key)
	{
		_aes = Aes.Create();
		_aes.Key = key.ToArray();
		_aes.Mode = CipherMode.ECB;
		_aes.Padding = PaddingMode.None;

		_encryptor = _aes.CreateEncryptor();
		_decryptor = _aes.CreateDecryptor();
	}

	public void Dispose()
	{
		_encryptor.Dispose();
		_decryptor.Dispose();
		_aes.Dispose();
	}

	public static bool IsSupported => true;

	public static BlockCipherHardwareAcceleration HardwareAcceleration => BlockCipherHardwareAcceleration.Unknown;

	public static DefaultAesCipher Create(in ReadOnlySpan<byte> key)
	{
		return new DefaultAesCipher(key);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void Transform(ICryptoTransform cryptoTransform, ReadOnlySpan<byte> input, Span<byte> output)
	{
		using CryptoArrayPool<byte> buffer = new(input.Length);
		input.CopyTo(buffer.Span);
		int length = cryptoTransform.TransformBlock(buffer.Array, 0, input.Length, buffer.Array, 0);
		buffer.Span.Slice(0, length).CopyTo(output);
	}

	[SkipLocalsInit]
	public VectorBuffer16 Encrypt(scoped in VectorBuffer16 source)
	{
		Unsafe.SkipInit(out VectorBuffer16 r);
		Transform(_encryptor, source, r);
		return r;
	}

	[SkipLocalsInit]
	public VectorBuffer16 Decrypt(scoped in VectorBuffer16 source)
	{
		Unsafe.SkipInit(out VectorBuffer16 r);
		Transform(_decryptor, source, r);
		return r;
	}

	[SkipLocalsInit]
	public VectorBuffer32 Encrypt(scoped in VectorBuffer32 source)
	{
		Unsafe.SkipInit(out VectorBuffer32 r);
		Transform(_encryptor, source, r);
		return r;
	}

	[SkipLocalsInit]
	public VectorBuffer32 Decrypt(scoped in VectorBuffer32 source)
	{
		Unsafe.SkipInit(out VectorBuffer32 r);
		Transform(_decryptor, source, r);
		return r;
	}

	[SkipLocalsInit]
	public VectorBuffer64 Encrypt(scoped in VectorBuffer64 source)
	{
		Unsafe.SkipInit(out VectorBuffer64 r);
		Transform(_encryptor, source, r);
		return r;
	}

	[SkipLocalsInit]
	public VectorBuffer64 Decrypt(scoped in VectorBuffer64 source)
	{
		Unsafe.SkipInit(out VectorBuffer64 r);
		Transform(_decryptor, source, r);
		return r;
	}

	[SkipLocalsInit]
	public VectorBuffer128 Encrypt(scoped in VectorBuffer128 source)
	{
		Unsafe.SkipInit(out VectorBuffer128 r);
		Transform(_encryptor, source, r);
		return r;
	}

	[SkipLocalsInit]
	public VectorBuffer128 Decrypt(scoped in VectorBuffer128 source)
	{
		Unsafe.SkipInit(out VectorBuffer128 r);
		Transform(_decryptor, source, r);
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
