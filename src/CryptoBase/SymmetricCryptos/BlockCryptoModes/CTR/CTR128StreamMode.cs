using CryptoBase.Abstractions.SymmetricCryptos;

namespace CryptoBase.SymmetricCryptos.BlockCryptoModes.CTR;

public class CTR128StreamMode : IStreamBlockCryptoMode
{
	public string Name => InternalBlockCrypto.Name + @"-CTR";

	public IBlockCrypto InternalBlockCrypto { get; init; }

	public ReadOnlyMemory<byte> Iv { get; init; }

	private readonly byte[] _counter;
	private readonly byte[] _keyStream;

	private int _index;

	private const int BlockSize = 16;

	public CTR128StreamMode(IBlockCrypto crypto, ReadOnlySpan<byte> iv)
	{
		InternalBlockCrypto = crypto;
		Iv = iv.ToArray();

		if (InternalBlockCrypto.BlockSize is not BlockSize)
		{
			throw new InvalidOperationException($@"Support {BlockSize} bytes block size only");
		}

		if (Iv.Length > BlockSize)
		{
			throw new ArgumentException($@"IV length > {BlockSize} bytes", nameof(iv));
		}

		_counter = ArrayPool<byte>.Shared.Rent(BlockSize);
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
			if (_index is 0)
			{
				UpdateKeyStream();
			}

			int r = BlockSize - _index;
			IntrinsicsUtils.Xor(stream + _index, source, destination, Math.Min(r, length));

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

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private void UpdateKeyStream()
	{
		InternalBlockCrypto.Encrypt(_counter, _keyStream);

		UpdateCounter();
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private void UpdateCounter()
	{
		_counter.AsSpan(0, BlockSize).FixedTimeIncrementBigEndian();
	}

	public void Reset()
	{
		InternalBlockCrypto.Reset();
		_index = 0;

		Span<byte> c = _counter.AsSpan(0, BlockSize);
		c[Iv.Length..].Clear();
		Iv.Span.CopyTo(c);
	}

	public void Dispose()
	{
		InternalBlockCrypto.Dispose();

		ArrayPool<byte>.Shared.Return(_counter);
		ArrayPool<byte>.Shared.Return(_keyStream);

		GC.SuppressFinalize(this);
	}
}
