namespace CryptoBase.SymmetricCryptos.BlockCryptoModes;

/// <summary>
/// Provides stateful CFB-128 encryption or decryption over a 16-byte block cipher.
/// </summary>
/// <typeparam name="TBlockCipher">The block cipher type.</typeparam>
public sealed class CfbMode128<TBlockCipher> : IStreamCrypto where TBlockCipher : IBlock16Cipher<TBlockCipher>
{
	/// <inheritdoc/>
	public string Name => _blockCipher.Name + @"-CFB";

	private readonly bool _isEncrypt;
	private readonly TBlockCipher _blockCipher;
	private readonly bool _disposeCipher;

	private int _index;
	private VectorBuffer16 _iv;
	private VectorBuffer16 _block;
	private VectorBuffer16 _keyStream;

	private const int BlockSize = 16;

	/// <summary>
	/// Initializes a CFB-128 encryptor or decryptor.
	/// </summary>
	/// <param name="isEncrypt"><see langword="true"/> to encrypt; <see langword="false"/> to decrypt.</param>
	/// <param name="blockCipher">The block cipher.</param>
	/// <param name="iv">The 16-byte initialization vector.</param>
	/// <param name="disposeCipher">Whether to dispose <paramref name="blockCipher"/> with this instance.</param>
	public CfbMode128(bool isEncrypt, TBlockCipher blockCipher, ReadOnlySpan<byte> iv, bool disposeCipher = true)
	{
		ArgumentOutOfRangeException.ThrowIfNotEqual(iv.Length, BlockSize, nameof(iv));

		_isEncrypt = isEncrypt;
		_blockCipher = blockCipher;
		_disposeCipher = disposeCipher;

		_iv = iv.AsVectorBuffer16();

		Reset();
	}

	/// <inheritdoc/>
	public void Dispose()
	{
		_iv.ZeroMemory();
		_block.ZeroMemory();
		_keyStream.ZeroMemory();

		if (_disposeCipher)
		{
			_blockCipher.Dispose();
		}
	}

	/// <inheritdoc/>
	public void Reset()
	{
		_index = 0;
		_block = _iv;
	}

	/// <inheritdoc/>
	public void Update(ReadOnlySpan<byte> source, Span<byte> destination)
	{
		ArgumentOutOfRangeException.ThrowIfLessThan(destination.Length, source.Length, nameof(destination));

		int i = 0;
		int length = source.Length;

		Span<byte> block = _block.AsSpan();
		Span<byte> stream = _keyStream.AsSpan();

		if (_index is not 0)
		{
			int len = Math.Min(length, BlockSize - _index);
			FastUtils.Xor(stream.Slice(_index, len), source.Slice(0, len), destination.Slice(0, len), len);
			(_isEncrypt ? destination : source).Slice(0, len).CopyTo(block.Slice(_index));

			i += len;
			length -= len;

			if (length <= 0)
			{
				_index += len;
				return;
			}

			_index = 0;
		}

		while (length >= BlockSize)
		{
			_keyStream = _blockCipher.Encrypt(_block);

			destination.Slice(i).AsVectorBuffer16() = source.Slice(i).AsVectorBuffer16() ^ _keyStream;
			(_isEncrypt ? destination : source).Slice(i, BlockSize).CopyTo(block);

			i += BlockSize;
			length -= BlockSize;
		}

		if (length is 0)
		{
			return;
		}

		_index = length;
		_keyStream = _blockCipher.Encrypt(_block);
		FastUtils.Xor(stream.Slice(0, length), source.Slice(i, length), destination.Slice(i, length), length);
		(_isEncrypt ? destination : source).Slice(i, length).CopyTo(block);
	}
}
