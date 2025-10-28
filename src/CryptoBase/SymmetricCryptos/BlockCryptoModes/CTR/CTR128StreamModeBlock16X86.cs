using CryptoBase.Abstractions.SymmetricCryptos;

namespace CryptoBase.SymmetricCryptos.BlockCryptoModes.CTR;

public sealed class CTR128StreamModeBlock16X86 : IStreamCrypto
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

		_iCounter = FastUtils.BroadcastVector128ToVector256(ref iv.GetReference()).ReverseEndianness128().IncUpper128Le();

		Reset();
	}

	public void Update(ReadOnlySpan<byte> source, Span<byte> destination)
	{
		ArgumentOutOfRangeException.ThrowIfLessThan(destination.Length, source.Length, nameof(destination));

		int length = source.Length;
		int offset = 0;
		ReadOnlySpan<byte> keyStream = _keyStream;

		while (length > 0)
		{
			if (_index is 0)
			{
				UpdateKeyStream();
			}

			int r = BlockSize16 - _index;
			FastUtils.Xor(keyStream.Slice(_index), source.Slice(offset), destination.Slice(offset), Math.Min(r, length));

			if (length < r)
			{
				_index += length;
				return;
			}

			_index = 0;
			length -= r;
			offset += r;
		}
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private void UpdateKeyStream()
	{
		Span<byte> c = _counter.AsSpan(0, BlockSize16);

		Vector256<byte> v0 = _counterV0.ReverseEndianness128();
		Vector256<byte> v1 = _counterV1.ReverseEndianness128();
		Vector256<byte> v2 = _counterV2.ReverseEndianness128();
		Vector256<byte> v3 = _counterV3.ReverseEndianness128();
		Vector256<byte> v4 = _counterV4.ReverseEndianness128();
		Vector256<byte> v5 = _counterV5.ReverseEndianness128();
		Vector256<byte> v6 = _counterV6.ReverseEndianness128();
		Vector256<byte> v7 = _counterV7.ReverseEndianness128();

		ref byte cRef = ref c.GetReference();
		Unsafe.WriteUnaligned(ref Unsafe.Add(ref cRef, 0 * 2 * BlockSize), v0);
		Unsafe.WriteUnaligned(ref Unsafe.Add(ref cRef, 1 * 2 * BlockSize), v1);
		Unsafe.WriteUnaligned(ref Unsafe.Add(ref cRef, 2 * 2 * BlockSize), v2);
		Unsafe.WriteUnaligned(ref Unsafe.Add(ref cRef, 3 * 2 * BlockSize), v3);
		Unsafe.WriteUnaligned(ref Unsafe.Add(ref cRef, 4 * 2 * BlockSize), v4);
		Unsafe.WriteUnaligned(ref Unsafe.Add(ref cRef, 5 * 2 * BlockSize), v5);
		Unsafe.WriteUnaligned(ref Unsafe.Add(ref cRef, 6 * 2 * BlockSize), v6);
		Unsafe.WriteUnaligned(ref Unsafe.Add(ref cRef, 7 * 2 * BlockSize), v7);

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
	}
}
