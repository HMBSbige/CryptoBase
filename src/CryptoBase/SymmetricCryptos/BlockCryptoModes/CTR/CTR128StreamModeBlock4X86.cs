using CryptoBase.Abstractions.SymmetricCryptos;

namespace CryptoBase.SymmetricCryptos.BlockCryptoModes.CTR;

public class CTR128StreamModeBlock4X86 : IStreamCrypto
{
	public string Name => _internalBlockCrypto.Name + @"-CTR";

	private readonly IBlockCrypto _internalBlockCrypto;

	private readonly byte[] _counter;
	private readonly byte[] _keyStream;
	private readonly Vector128<byte> _iCounter;
	private Vector128<byte> _counterV0;
	private Vector128<byte> _counterV1;
	private Vector128<byte> _counterV2;
	private Vector128<byte> _counterV3;

	private int _index;

	private const int BlockSize = 16;
	private const int BlockSize4 = 4 * BlockSize;

	public unsafe CTR128StreamModeBlock4X86(IBlockCrypto crypto, ReadOnlySpan<byte> iv)
	{
		ArgumentOutOfRangeException.ThrowIfNotEqual(crypto.BlockSize, BlockSize4);

		ArgumentOutOfRangeException.ThrowIfGreaterThan(iv.Length, BlockSize, nameof(iv));

		_internalBlockCrypto = crypto;

		_counter = ArrayPool<byte>.Shared.Rent(BlockSize4);
		_keyStream = ArrayPool<byte>.Shared.Rent(BlockSize4);

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
		ArgumentOutOfRangeException.ThrowIfLessThan(destination.Length, source.Length, nameof(destination));

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

			int r = BlockSize4 - _index;
			int xorLen = Math.Min(r, length);
			IntrinsicsUtils.Xor(
				new ReadOnlySpan<byte>(stream + _index, xorLen),
				new ReadOnlySpan<byte>(source, xorLen),
				new Span<byte>(destination, xorLen),
				xorLen);

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
		Span<byte> c = _counter.AsSpan(0, BlockSize4);

		fixed (byte* p = c)
		{
			Sse2.Store(p + 0 * BlockSize, _counterV0.ReverseEndianness128());
			Sse2.Store(p + 1 * BlockSize, _counterV1.ReverseEndianness128());
			Sse2.Store(p + 2 * BlockSize, _counterV2.ReverseEndianness128());
			Sse2.Store(p + 3 * BlockSize, _counterV3.ReverseEndianness128());
		}

		_internalBlockCrypto.Encrypt(c, _keyStream);

		_counterV0 = _counterV3.Inc128Le();
		_counterV1 = _counterV0.Inc128Le();
		_counterV2 = _counterV1.Inc128Le();
		_counterV3 = _counterV2.Inc128Le();
	}

	public void Reset()
	{
		_internalBlockCrypto.Reset();
		_index = 0;
		_counterV0 = _iCounter;
		_counterV1 = _counterV0.Inc128Le();
		_counterV2 = _counterV1.Inc128Le();
		_counterV3 = _counterV2.Inc128Le();
	}

	public void Dispose()
	{
		_internalBlockCrypto.Dispose();

		ArrayPool<byte>.Shared.Return(_counter);
		ArrayPool<byte>.Shared.Return(_keyStream);

		GC.SuppressFinalize(this);
	}
}
