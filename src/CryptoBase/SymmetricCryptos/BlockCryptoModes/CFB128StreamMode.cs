using CryptoBase.Abstractions.SymmetricCryptos;

namespace CryptoBase.SymmetricCryptos.BlockCryptoModes;

public class CFB128StreamMode : IStreamBlockCryptoMode
{
	public string Name => @"AES-CFB";

	public IBlockCrypto InternalBlockCrypto { get; init; }

	public ReadOnlyMemory<byte> Iv { get; init; }

	private readonly bool _isEncrypt;

	private readonly byte[] _block;
	private readonly byte[] _keyStream;

	private int _index;

	private const int BlockSize = 16;

	public CFB128StreamMode(bool isEncrypt, IBlockCrypto crypto, ReadOnlySpan<byte> iv)
	{
		if (crypto.BlockSize is not 16)
		{
			throw new ArgumentException(@"Block size must be 16 bytes", nameof(crypto));
		}

		if (iv.Length is not 16)
		{
			throw new ArgumentException(@"IV length must be 16 bytes", nameof(iv));
		}

		_isEncrypt = isEncrypt;
		InternalBlockCrypto = crypto;
		Iv = iv.ToArray();

		_block = ArrayPool<byte>.Shared.Rent(BlockSize);
		_keyStream = ArrayPool<byte>.Shared.Rent(BlockSize);

		Reset();
	}

	public unsafe void Update(ReadOnlySpan<byte> source, Span<byte> destination)
	{
		if (destination.Length < source.Length)
		{
			throw new ArgumentException(string.Empty, nameof(destination));
		}

		int length = source.Length;
		fixed (byte* pStream = _keyStream)
		fixed (byte* pSource = source)
		fixed (byte* pDestination = destination)
		{
			Update(length, pStream, pSource, pDestination);
		}
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private unsafe void Update(int length, byte* stream, byte* source, byte* destination)
	{
		while (length > 0)
		{
			if (_index == 0)
			{
				InternalBlockCrypto.Encrypt(_block, _keyStream);
			}

			int r = BlockSize - _index;

			int len = Math.Min(length, r);
			IntrinsicsUtils.Xor(stream + _index, source, destination, len);

			fixed (byte* block = _block)
			{
				Unsafe.CopyBlockUnaligned(block + _index, _isEncrypt ? destination : source, (uint)len);
			}

			if (length < r)
			{
				_index += length;
				return;
			}

			_index = 0;
			length -= r;
			source += r;
			destination += r;
		}
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
	}
}
