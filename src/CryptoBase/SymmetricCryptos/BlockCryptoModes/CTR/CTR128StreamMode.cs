using CryptoBase.Abstractions.SymmetricCryptos;

namespace CryptoBase.SymmetricCryptos.BlockCryptoModes.CTR;

public class CTR128StreamMode : IStreamCrypto
{
	public string Name => _internalBlockCrypto.Name + @"-CTR";

	private readonly IBlockCrypto _internalBlockCrypto;

	private readonly ReadOnlyMemory<byte> _iv;

	private readonly byte[] _counter;
	private readonly byte[] _keyStream;

	private int _index;

	private const int BlockSize = 16;

	public CTR128StreamMode(IBlockCrypto crypto, ReadOnlySpan<byte> iv)
	{
		ArgumentOutOfRangeException.ThrowIfNotEqual(crypto.BlockSize, BlockSize);
		ArgumentOutOfRangeException.ThrowIfGreaterThan(iv.Length, BlockSize, nameof(iv));

		_internalBlockCrypto = crypto;
		_iv = iv.ToArray();

		_counter = ArrayPool<byte>.Shared.Rent(BlockSize);
		_keyStream = ArrayPool<byte>.Shared.Rent(BlockSize);

		Reset();
	}

	public void Update(ReadOnlySpan<byte> source, Span<byte> destination)
	{
		ArgumentOutOfRangeException.ThrowIfLessThan(destination.Length, source.Length, nameof(destination));

		UpdateCore(source, destination);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private void UpdateCore(ReadOnlySpan<byte> source, Span<byte> destination)
	{
		int i = 0;
		int left = source.Length;

		IBlockCrypto crypto = _internalBlockCrypto;
		Span<byte> counter = _counter.AsSpan(0, BlockSize);
		Span<byte> stream = _keyStream.AsSpan(0, BlockSize);

		while (left > 0)
		{
			if (_index is 0)
			{
				crypto.Encrypt(counter, stream);

				ref byte counterRef = ref counter.GetReference();
				ref UInt128 c = ref Unsafe.As<byte, UInt128>(ref counterRef);
				c = BinaryPrimitives.ReverseEndianness(BinaryPrimitives.ReverseEndianness(c) + 1);
			}

			if (left >= BlockSize && _index is 0)
			{
				FastUtils.Xor16(stream, source.Slice(i), destination.Slice(i));

				left -= BlockSize;
				i += BlockSize;
			}
			else
			{
				int r = BlockSize - _index;

				FastUtils.XorLess16(stream.Slice(_index), source.Slice(i), destination.Slice(i), Math.Min(r, left));

				if (left < r)
				{
					_index += left;
					return;
				}

				_index = 0;
				left -= r;
				i += r;
			}
		}
	}

	public void Reset()
	{
		_internalBlockCrypto.Reset();
		_index = 0;

		Span<byte> c = _counter.AsSpan(0, BlockSize);
		c.Clear();
		_iv.Span.CopyTo(c);
	}

	public void Dispose()
	{
		_internalBlockCrypto.Dispose();

		ArrayPool<byte>.Shared.Return(_counter);
		ArrayPool<byte>.Shared.Return(_keyStream);

		GC.SuppressFinalize(this);
	}
}
