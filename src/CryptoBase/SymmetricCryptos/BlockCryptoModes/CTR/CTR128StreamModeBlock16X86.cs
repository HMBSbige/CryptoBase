using CryptoBase.Abstractions.SymmetricCryptos;

namespace CryptoBase.SymmetricCryptos.BlockCryptoModes.CTR;

public class CTR128StreamModeBlock16X86 : IStreamCrypto
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
	private Vector256<byte> _counterV4;
	private Vector256<byte> _counterV5;
	private Vector256<byte> _counterV6;
	private Vector256<byte> _counterV7;

	private int _index;

	private const int BlockSize = 16;
	private const int BlockSize16 = 16 * BlockSize;

	public CTR128StreamModeBlock16X86(IBlockCrypto crypto, ReadOnlySpan<byte> iv)
	{
		ArgumentOutOfRangeException.ThrowIfNotEqual(crypto.BlockSize, BlockSize16);
		ArgumentOutOfRangeException.ThrowIfGreaterThan(iv.Length, BlockSize, nameof(iv));

		_internalBlockCrypto = crypto;

		_counter = ArrayPool<byte>.Shared.Rent(BlockSize16);
		_keyStream = ArrayPool<byte>.Shared.Rent(BlockSize16);

		Span<byte> c = stackalloc byte[BlockSize];
		iv.CopyTo(c);

		var vec = Unsafe.ReadUnaligned<Vector128<byte>>(ref MemoryMarshal.GetReference(c));
		_iCounter = Vector256.Create(vec, vec).ReverseEndianness128().IncUpper128Le();

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

			int r = BlockSize16 - _index;
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
		Span<byte> c = _counter.AsSpan(0, BlockSize16);
		ref byte cRef = ref MemoryMarshal.GetReference(c);

		Unsafe.WriteUnaligned(ref Unsafe.Add(ref cRef, 0 * 2 * BlockSize), _counterV0.ReverseEndianness128());
		Unsafe.WriteUnaligned(ref Unsafe.Add(ref cRef, 1 * 2 * BlockSize), _counterV1.ReverseEndianness128());
		Unsafe.WriteUnaligned(ref Unsafe.Add(ref cRef, 2 * 2 * BlockSize), _counterV2.ReverseEndianness128());
		Unsafe.WriteUnaligned(ref Unsafe.Add(ref cRef, 3 * 2 * BlockSize), _counterV3.ReverseEndianness128());
		Unsafe.WriteUnaligned(ref Unsafe.Add(ref cRef, 4 * 2 * BlockSize), _counterV4.ReverseEndianness128());
		Unsafe.WriteUnaligned(ref Unsafe.Add(ref cRef, 5 * 2 * BlockSize), _counterV5.ReverseEndianness128());
		Unsafe.WriteUnaligned(ref Unsafe.Add(ref cRef, 6 * 2 * BlockSize), _counterV6.ReverseEndianness128());
		Unsafe.WriteUnaligned(ref Unsafe.Add(ref cRef, 7 * 2 * BlockSize), _counterV7.ReverseEndianness128());

		_internalBlockCrypto.Encrypt(c, _keyStream);

		_counterV0 = _counterV7.AddTwo128Le();
		_counterV1 = _counterV0.AddTwo128Le();
		_counterV2 = _counterV1.AddTwo128Le();
		_counterV3 = _counterV2.AddTwo128Le();
		_counterV4 = _counterV3.AddTwo128Le();
		_counterV5 = _counterV4.AddTwo128Le();
		_counterV6 = _counterV5.AddTwo128Le();
		_counterV7 = _counterV6.AddTwo128Le();
	}

	public void Reset()
	{
		_internalBlockCrypto.Reset();
		_index = 0;
		_counterV0 = _iCounter;
		_counterV1 = _counterV0.AddTwo128Le();
		_counterV2 = _counterV1.AddTwo128Le();
		_counterV3 = _counterV2.AddTwo128Le();
		_counterV4 = _counterV3.AddTwo128Le();
		_counterV5 = _counterV4.AddTwo128Le();
		_counterV6 = _counterV5.AddTwo128Le();
		_counterV7 = _counterV6.AddTwo128Le();
	}

	public void Dispose()
	{
		_internalBlockCrypto.Dispose();

		ArrayPool<byte>.Shared.Return(_counter);
		ArrayPool<byte>.Shared.Return(_keyStream);

		GC.SuppressFinalize(this);
	}
}
