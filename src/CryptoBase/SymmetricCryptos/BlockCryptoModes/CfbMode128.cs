namespace CryptoBase.SymmetricCryptos.BlockCryptoModes;

public sealed class CfbMode128<TBlockCipher> : IStreamCrypto where TBlockCipher : IBlock16Cipher<TBlockCipher>
{
	public string Name => _blockCipher.Name + @"-CFB";

	private readonly bool _isEncrypt;
	private readonly TBlockCipher _blockCipher;
	private readonly bool _disposeCipher;

	private int _index;
	private readonly CryptoArrayPool<byte> _iv = new(BlockSize);
	private readonly CryptoArrayPool<byte> _block = new(BlockSize);
	private readonly CryptoArrayPool<byte> _keyStream = new(BlockSize);

	private const int BlockSize = 16;

	public CfbMode128(bool isEncrypt, TBlockCipher blockCipher, ReadOnlySpan<byte> iv, bool disposeCipher = true)
	{
		ArgumentOutOfRangeException.ThrowIfNotEqual(iv.Length, BlockSize, nameof(iv));

		_isEncrypt = isEncrypt;
		_blockCipher = blockCipher;
		_disposeCipher = disposeCipher;

		Span<byte> ivSpan = _iv.Span;
		ivSpan.Clear();
		iv.CopyTo(_iv.Span);

		Reset();
	}

	public void Dispose()
	{
		_iv.Dispose();
		_block.Dispose();
		_keyStream.Dispose();

		if (_disposeCipher)
		{
			_blockCipher.Dispose();
		}
	}

	public void Reset()
	{
		_index = 0;
		_iv.Span.CopyTo(_block.Span);
	}

	public void Update(ReadOnlySpan<byte> source, Span<byte> destination)
	{
		ArgumentOutOfRangeException.ThrowIfLessThan(destination.Length, source.Length, nameof(destination));

		int i = 0;
		int length = source.Length;

		Span<byte> block = _block.Span;
		Span<byte> stream = _keyStream.Span;
		ref VectorBuffer16 c = ref block.AsVectorBuffer16();
		ref VectorBuffer16 ks = ref stream.AsVectorBuffer16();

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
			ks = _blockCipher.Encrypt(c);

			destination.Slice(i).AsVectorBuffer16() = source.Slice(i).AsVectorBuffer16() ^ stream.AsVectorBuffer16();
			(_isEncrypt ? destination : source).Slice(i, BlockSize).CopyTo(block);

			i += BlockSize;
			length -= BlockSize;
		}

		_index = length;
		ks = _blockCipher.Encrypt(c);
		FastUtils.Xor(stream.Slice(0, length), source.Slice(i, length), destination.Slice(i, length), length);
		(_isEncrypt ? destination : source).Slice(i, length).CopyTo(block);
	}
}
