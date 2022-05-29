using CryptoBase.Abstractions.SymmetricCryptos;

namespace CryptoBase.SymmetricCryptos.BlockCryptoModes.CTR;

public class CTR128StreamModeBlock8X86 : IStreamBlockCryptoMode
{
	public string Name => InternalBlockCrypto.Name + @"-CTR";

	public IBlockCrypto InternalBlockCrypto { get; init; }

	public ReadOnlyMemory<byte> Iv { get; init; }

	private readonly byte[] _counter;
	private readonly byte[] _keyStream;
	private readonly Vector128<byte> _iCounter;
	private Vector128<byte> _counterV0;
	private Vector128<byte> _counterV1;
	private Vector128<byte> _counterV2;
	private Vector128<byte> _counterV3;
	private Vector128<byte> _counterV4;
	private Vector128<byte> _counterV5;
	private Vector128<byte> _counterV6;
	private Vector128<byte> _counterV7;

	private int _index;

	private const int BlockSize = 16;
	private const int BlockSize8 = 8 * BlockSize;

	public unsafe CTR128StreamModeBlock8X86(IBlockCrypto crypto, ReadOnlySpan<byte> iv)
	{
		InternalBlockCrypto = crypto;
		Iv = iv.ToArray();

		if (InternalBlockCrypto.BlockSize is not BlockSize8)
		{
			throw new InvalidOperationException($@"Support {BlockSize8} bytes block size only");
		}

		if (Iv.Length > BlockSize)
		{
			throw new ArgumentException($@"IV length > {BlockSize} bytes", nameof(iv));
		}

		_counter = ArrayPool<byte>.Shared.Rent(BlockSize8);
		_keyStream = ArrayPool<byte>.Shared.Rent(BlockSize8);

		Span<byte> c = stackalloc byte[BlockSize];
		iv.CopyTo(c);
		fixed (byte* p = c)
		{
			_iCounter = Sse2.LoadVector128(p).ReverseEndianness128();
		}

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

			int r = BlockSize8 - _index;
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
	private unsafe void UpdateKeyStream()
	{
		Span<byte> c = _counter.AsSpan(0, BlockSize8);

		fixed (byte* p = c)
		{
			Sse2.Store(p + 0 * BlockSize, _counterV0.ReverseEndianness128());
			Sse2.Store(p + 1 * BlockSize, _counterV1.ReverseEndianness128());
			Sse2.Store(p + 2 * BlockSize, _counterV2.ReverseEndianness128());
			Sse2.Store(p + 3 * BlockSize, _counterV3.ReverseEndianness128());
			Sse2.Store(p + 4 * BlockSize, _counterV4.ReverseEndianness128());
			Sse2.Store(p + 5 * BlockSize, _counterV5.ReverseEndianness128());
			Sse2.Store(p + 6 * BlockSize, _counterV6.ReverseEndianness128());
			Sse2.Store(p + 7 * BlockSize, _counterV7.ReverseEndianness128());
		}

		InternalBlockCrypto.Encrypt(c, _keyStream);

		_counterV0 = _counterV7.Inc128Le();
		_counterV1 = _counterV0.Inc128Le();
		_counterV2 = _counterV1.Inc128Le();
		_counterV3 = _counterV2.Inc128Le();
		_counterV4 = _counterV3.Inc128Le();
		_counterV5 = _counterV4.Inc128Le();
		_counterV6 = _counterV5.Inc128Le();
		_counterV7 = _counterV6.Inc128Le();
	}

	public void Reset()
	{
		InternalBlockCrypto.Reset();
		_index = 0;
		_counterV0 = _iCounter;
		_counterV1 = _counterV0.Inc128Le();
		_counterV2 = _counterV1.Inc128Le();
		_counterV3 = _counterV2.Inc128Le();
		_counterV4 = _counterV3.Inc128Le();
		_counterV5 = _counterV4.Inc128Le();
		_counterV6 = _counterV5.Inc128Le();
		_counterV7 = _counterV6.Inc128Le();
	}

	public void Dispose()
	{
		InternalBlockCrypto.Dispose();

		ArrayPool<byte>.Shared.Return(_counter);
		ArrayPool<byte>.Shared.Return(_keyStream);

		GC.SuppressFinalize(this);
	}
}
