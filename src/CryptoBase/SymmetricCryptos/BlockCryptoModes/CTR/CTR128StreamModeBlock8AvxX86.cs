using CryptoBase.Abstractions.SymmetricCryptos;

namespace CryptoBase.SymmetricCryptos.BlockCryptoModes.CTR;

public class CTR128StreamModeBlock8AvxX86 : IStreamCrypto
{
	public string Name => _internalBlockCrypto.Name + @"-CTR";

	private readonly IBlockCrypto _internalBlockCrypto;

	private readonly byte[] _counter;
	private readonly byte[] _keyStream;
	private readonly Vector256<byte> _iCounter;
	private Vector256<byte> _counterV0;
	private Vector256<byte> _counterV1;
	private Vector256<byte> _counterV2;
	private Vector256<byte> _counterV3;

	private int _index;

	private const int BlockSize = 16;
	private const int BlockSize8 = 8 * BlockSize;

	public unsafe CTR128StreamModeBlock8AvxX86(IBlockCrypto crypto, ReadOnlySpan<byte> iv)
	{
		ArgumentOutOfRangeException.ThrowIfNotEqual(crypto.BlockSize, BlockSize8);

		ArgumentOutOfRangeException.ThrowIfGreaterThan(iv.Length, BlockSize, nameof(iv));

		_internalBlockCrypto = crypto;

		_counter = ArrayPool<byte>.Shared.Rent(BlockSize8);
		_keyStream = ArrayPool<byte>.Shared.Rent(BlockSize8);

		Span<byte> c = stackalloc byte[BlockSize];
		iv.CopyTo(c);

		fixed (byte* p = c)
		{
			_iCounter = Avx2.BroadcastVector128ToVector256(p).ReverseEndianness128().IncUpper128Le();
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
			Avx.Store(p + 0 * 2 * BlockSize, _counterV0.ReverseEndianness128());
			Avx.Store(p + 1 * 2 * BlockSize, _counterV1.ReverseEndianness128());
			Avx.Store(p + 2 * 2 * BlockSize, _counterV2.ReverseEndianness128());
			Avx.Store(p + 3 * 2 * BlockSize, _counterV3.ReverseEndianness128());
		}

		_internalBlockCrypto.Encrypt(c, _keyStream);

		_counterV0 = _counterV3.AddTwo128Le();
		_counterV1 = _counterV0.AddTwo128Le();
		_counterV2 = _counterV1.AddTwo128Le();
		_counterV3 = _counterV2.AddTwo128Le();
	}

	public void Reset()
	{
		_internalBlockCrypto.Reset();
		_index = 0;
		_counterV0 = _iCounter;
		_counterV1 = _counterV0.AddTwo128Le();
		_counterV2 = _counterV1.AddTwo128Le();
		_counterV3 = _counterV2.AddTwo128Le();
	}

	public void Dispose()
	{
		_internalBlockCrypto.Dispose();

		ArrayPool<byte>.Shared.Return(_counter);
		ArrayPool<byte>.Shared.Return(_keyStream);

		GC.SuppressFinalize(this);
	}
}
