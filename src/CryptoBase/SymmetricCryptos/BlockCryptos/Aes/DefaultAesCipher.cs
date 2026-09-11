using BclAes = System.Security.Cryptography.Aes;

namespace CryptoBase.SymmetricCryptos.BlockCryptos.Aes;

internal readonly struct DefaultAesCipher : IBlock16Cipher<DefaultAesCipher>
{
	public string Name => @"AES";

	private const int MaxBufferSize = 128;

	private readonly BclAes _aes;
	private readonly ICryptoTransform _encryptor;
	private readonly ICryptoTransform _decryptor;
	private readonly byte[] _buffer;

	private DefaultAesCipher(in ReadOnlySpan<byte> key)
	{
		_aes = BclAes.Create();
		_aes.SetKey(key);
		_aes.Mode = CipherMode.ECB;
		_aes.Padding = PaddingMode.None;

		_encryptor = _aes.CreateEncryptor();
		_decryptor = _aes.CreateDecryptor();
		_buffer = new byte[MaxBufferSize];
	}

	public void Dispose()
	{
		_encryptor.Dispose();
		_decryptor.Dispose();
		_aes.Dispose();

		_buffer.AsSpan().ZeroMemory();
	}

	public static bool IsSupported => true;

	public static BlockCipherHardwareAcceleration HardwareAcceleration => BlockCipherHardwareAcceleration.Unknown;

	public static DefaultAesCipher Create(in ReadOnlySpan<byte> key)
	{
		return new DefaultAesCipher(key);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private void Transform(ICryptoTransform cryptoTransform, ReadOnlySpan<byte> input, Span<byte> output)
	{
		input.CopyTo(_buffer);
		int length = cryptoTransform.TransformBlock(_buffer, 0, input.Length, _buffer, 0);
		_buffer.AsSpan(0, length).CopyTo(output);
	}

	[SkipLocalsInit]
	public VectorBuffer16 Encrypt(VectorBuffer16 source)
	{
		Unsafe.SkipInit(out VectorBuffer16 r);
		Transform(_encryptor, source, r);
		return r;
	}

	[SkipLocalsInit]
	public VectorBuffer16 Decrypt(VectorBuffer16 source)
	{
		Unsafe.SkipInit(out VectorBuffer16 r);
		Transform(_decryptor, source, r);
		return r;
	}

	[SkipLocalsInit]
	public VectorBuffer32 Encrypt(in VectorBuffer32 source)
	{
		Unsafe.SkipInit(out VectorBuffer32 r);
		Transform(_encryptor, source, r);
		return r;
	}

	[SkipLocalsInit]
	public VectorBuffer32 Decrypt(in VectorBuffer32 source)
	{
		Unsafe.SkipInit(out VectorBuffer32 r);
		Transform(_decryptor, source, r);
		return r;
	}

	[SkipLocalsInit]
	public VectorBuffer64 Encrypt(in VectorBuffer64 source)
	{
		Unsafe.SkipInit(out VectorBuffer64 r);
		Transform(_encryptor, source, r);
		return r;
	}

	[SkipLocalsInit]
	public VectorBuffer64 Decrypt(in VectorBuffer64 source)
	{
		Unsafe.SkipInit(out VectorBuffer64 r);
		Transform(_decryptor, source, r);
		return r;
	}

	[SkipLocalsInit]
	public VectorBuffer128 Encrypt(in VectorBuffer128 source)
	{
		Unsafe.SkipInit(out VectorBuffer128 r);
		Transform(_encryptor, source, r);
		return r;
	}

	[SkipLocalsInit]
	public VectorBuffer128 Decrypt(in VectorBuffer128 source)
	{
		Unsafe.SkipInit(out VectorBuffer128 r);
		Transform(_decryptor, source, r);
		return r;
	}

	public VectorBuffer128 EncryptV256(in VectorBuffer128 source)
	{
		ThrowHelper.ThrowNotSupported();
		return default;
	}

	public VectorBuffer128 DecryptV256(in VectorBuffer128 source)
	{
		ThrowHelper.ThrowNotSupported();
		return default;
	}

	public VectorBuffer256 EncryptV256(in VectorBuffer256 source)
	{
		ThrowHelper.ThrowNotSupported();
		return default;
	}

	public VectorBuffer256 DecryptV256(in VectorBuffer256 source)
	{
		ThrowHelper.ThrowNotSupported();
		return default;
	}

	public VectorBuffer256 EncryptV512(in VectorBuffer256 source)
	{
		ThrowHelper.ThrowNotSupported();
		return default;
	}

	public VectorBuffer256 DecryptV512(in VectorBuffer256 source)
	{
		ThrowHelper.ThrowNotSupported();
		return default;
	}

	public VectorBuffer512 EncryptV512(in VectorBuffer512 source)
	{
		ThrowHelper.ThrowNotSupported();
		return default;
	}

	public VectorBuffer512 DecryptV512(in VectorBuffer512 source)
	{
		ThrowHelper.ThrowNotSupported();
		return default;
	}
}
