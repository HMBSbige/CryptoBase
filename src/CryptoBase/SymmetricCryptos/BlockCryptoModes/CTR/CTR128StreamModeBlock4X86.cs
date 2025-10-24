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

	public CTR128StreamModeBlock4X86(IBlockCrypto crypto, ReadOnlySpan<byte> iv)
	{
		ArgumentOutOfRangeException.ThrowIfNotEqual(crypto.BlockSize, BlockSize4);

		ArgumentOutOfRangeException.ThrowIfGreaterThan(iv.Length, BlockSize, nameof(iv));

		_internalBlockCrypto = crypto;

		_counter = ArrayPool<byte>.Shared.Rent(BlockSize4);
		_keyStream = ArrayPool<byte>.Shared.Rent(BlockSize4);

		Span<byte> c = stackalloc byte[BlockSize];
		iv.CopyTo(c);

		_iCounter = Unsafe.ReadUnaligned<Vector128<byte>>(ref MemoryMarshal.GetReference(c)).ReverseEndianness128();

		Reset();
	}

	public void Update(ReadOnlySpan<byte> source, Span<byte> destination)
	{
		ArgumentOutOfRangeException.ThrowIfLessThan(destination.Length, source.Length, nameof(destination));

		int length = source.Length;
		int sourceOffset = 0;
		int destOffset = 0;

		while (length > 0)
		{
			if (_index is 0)
			{
				UpdateKeyStream();
			}

			int r = BlockSize4 - _index;
			int xorLen = Math.Min(r, length);
			IntrinsicsUtils.Xor(
				_keyStream.AsSpan(_index, xorLen),
				source.Slice(sourceOffset, xorLen),
				destination.Slice(destOffset, xorLen),
				xorLen);

			if (length < r)
			{
				_index += length;
				return;
			}

			_index = 0;
			length -= r;
			sourceOffset += r;
			destOffset += r;
		}
	}



	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private void UpdateKeyStream()
	{
		Span<byte> c = _counter.AsSpan(0, BlockSize4);
		ref byte cRef = ref MemoryMarshal.GetReference(c);

		Unsafe.WriteUnaligned(ref cRef, _counterV0.ReverseEndianness128());
		Unsafe.WriteUnaligned(ref Unsafe.Add(ref cRef, 1 * BlockSize), _counterV1.ReverseEndianness128());
		Unsafe.WriteUnaligned(ref Unsafe.Add(ref cRef, 2 * BlockSize), _counterV2.ReverseEndianness128());
		Unsafe.WriteUnaligned(ref Unsafe.Add(ref cRef, 3 * BlockSize), _counterV3.ReverseEndianness128());

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
