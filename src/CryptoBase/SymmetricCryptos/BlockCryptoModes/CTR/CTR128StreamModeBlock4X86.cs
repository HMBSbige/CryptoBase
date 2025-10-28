using CryptoBase.Abstractions.SymmetricCryptos;

namespace CryptoBase.SymmetricCryptos.BlockCryptoModes.CTR;

public sealed class CTR128StreamModeBlock4X86 : IStreamCrypto
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

		ref Vector128<byte> v = ref Unsafe.As<byte, Vector128<byte>>(ref iv.GetReference());
		_iCounter = v.ReverseEndianness128();

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

			int r = BlockSize4 - _index;
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
		Span<byte> c = _counter.AsSpan(0, BlockSize4);

		Vector128<byte> v0 = _counterV0.ReverseEndianness128();
		Vector128<byte> v1 = _counterV1.ReverseEndianness128();
		Vector128<byte> v2 = _counterV2.ReverseEndianness128();
		Vector128<byte> v3 = _counterV3.ReverseEndianness128();

		ref byte cRef = ref c.GetReference();
		Unsafe.WriteUnaligned(ref Unsafe.Add(ref cRef, 0 * BlockSize), v0);
		Unsafe.WriteUnaligned(ref Unsafe.Add(ref cRef, 1 * BlockSize), v1);
		Unsafe.WriteUnaligned(ref Unsafe.Add(ref cRef, 2 * BlockSize), v2);
		Unsafe.WriteUnaligned(ref Unsafe.Add(ref cRef, 3 * BlockSize), v3);

		_internalBlockCrypto.Encrypt(c, _keyStream);

		_counterV0 = _counterV3.Inc128Le();
		_counterV1 = _counterV0.Inc128Le();
		_counterV2 = _counterV1.Inc128Le();
		_counterV3 = _counterV2.Inc128Le();
	}

	public void Reset()
	{
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
	}
}
