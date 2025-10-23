using CryptoBase.Abstractions.SymmetricCryptos;

namespace CryptoBase.SymmetricCryptos.BlockCryptoModes;

public class CFB128StreamMode : IStreamBlockCryptoMode
{
	public string Name => InternalBlockCrypto.Name + @"-CFB";

	public IBlockCrypto InternalBlockCrypto { get; init; }

	public ReadOnlyMemory<byte> Iv { get; init; }

	private readonly bool _isEncrypt;

	private readonly byte[] _block;
	private readonly byte[] _keyStream;

	private int _index;

	private const int BlockSize = 16;

	public CFB128StreamMode(bool isEncrypt, IBlockCrypto crypto, ReadOnlySpan<byte> iv)
	{
		ArgumentOutOfRangeException.ThrowIfNotEqual(crypto.BlockSize, 16, nameof(crypto));

		ArgumentOutOfRangeException.ThrowIfNotEqual(iv.Length, 16, nameof(iv));

		_isEncrypt = isEncrypt;
		InternalBlockCrypto = crypto;
		Iv = iv.ToArray();

		_block = ArrayPool<byte>.Shared.Rent(BlockSize);
		_keyStream = ArrayPool<byte>.Shared.Rent(BlockSize);

		Reset();
	}

	public void Update(ReadOnlySpan<byte> source, Span<byte> destination)
	{
		ArgumentOutOfRangeException.ThrowIfLessThan(destination.Length, source.Length, nameof(destination));

		int i = 0;
		int length = source.Length;

		Span<byte> stream = _keyStream.AsSpan(0, BlockSize);
		Span<byte> block = _block.AsSpan(0, BlockSize);

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
			InternalBlockCrypto.Encrypt(block, stream);

			FastUtils.Xor16(stream, source.Slice(i, BlockSize), destination.Slice(i, BlockSize));
			(_isEncrypt ? destination : source).Slice(i, BlockSize).CopyTo(block);

			i += BlockSize;
			length -= BlockSize;
		}

		_index = length;
		InternalBlockCrypto.Encrypt(block, stream);
		FastUtils.Xor(stream.Slice(0, length), source.Slice(i, length), destination.Slice(i, length), length);
		(_isEncrypt ? destination : source).Slice(i, length).CopyTo(block);
	}

	public void Reset()
	{
		InternalBlockCrypto.Reset();
		_index = 0;

		Iv.CopyTo(_block);
	}

	public void Dispose()
	{
		InternalBlockCrypto.Dispose();

		ArrayPool<byte>.Shared.Return(_block);
		ArrayPool<byte>.Shared.Return(_keyStream);

		GC.SuppressFinalize(this);
	}
}
