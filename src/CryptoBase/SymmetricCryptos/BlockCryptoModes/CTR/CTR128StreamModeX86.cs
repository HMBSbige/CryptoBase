using CryptoBase.Abstractions.SymmetricCryptos;

namespace CryptoBase.SymmetricCryptos.BlockCryptoModes.CTR;

public class CTR128StreamModeX86 : IStreamCrypto
{
	public string Name => _internalBlockCrypto.Name + @"-CTR";

	private readonly IBlockCrypto _internalBlockCrypto;

	private readonly Vector128<byte> _iCounter;
	private Vector128<byte> _counterV;

	private int _index;

	private const int BlockSize = 16;

	public CTR128StreamModeX86(IBlockCrypto crypto, ReadOnlySpan<byte> iv)
	{
		ArgumentOutOfRangeException.ThrowIfNotEqual(crypto.BlockSize, BlockSize);
		ArgumentOutOfRangeException.ThrowIfGreaterThan(iv.Length, BlockSize, nameof(iv));

		_internalBlockCrypto = crypto;

		ref byte ivRef = ref iv.GetReference();
		ref Vector128<byte> v = ref Unsafe.As<byte, Vector128<byte>>(ref ivRef);
		_iCounter = v.ReverseEndianness128();

		Reset();
	}

	public void Update(ReadOnlySpan<byte> source, Span<byte> destination)
	{
		ArgumentOutOfRangeException.ThrowIfLessThan(destination.Length, source.Length, nameof(destination));

		int i = 0;
		int length = source.Length;

		Span<byte> stream = stackalloc byte[BlockSize];
		Span<byte> c = stackalloc byte[BlockSize];

		if (_index is not 0)
		{
			_counterV.ReverseEndianness128().CopyTo(c);
			_internalBlockCrypto.Encrypt(c, stream);

			int l = Math.Min(length, BlockSize - _index);
			FastUtils.Xor(stream.Slice(_index, l), source.Slice(0, l), destination.Slice(0, l), l);

			i += l;
			length -= l;

			if (length <= 0)
			{
				_index += l;
				return;
			}

			_counterV = _counterV.Inc128Le();
			_index = 0;
		}

		while (length >= BlockSize)
		{
			_counterV.ReverseEndianness128().CopyTo(c);
			_internalBlockCrypto.Encrypt(c, stream);
			_counterV = _counterV.Inc128Le();

			FastUtils.Xor(stream, source.Slice(i, BlockSize), destination.Slice(i, BlockSize), BlockSize);

			i += BlockSize;
			length -= BlockSize;
		}

		_index = length;
		_counterV.ReverseEndianness128().CopyTo(c);
		_internalBlockCrypto.Encrypt(c, stream);
		FastUtils.Xor(stream.Slice(0, length), source.Slice(i, length), destination.Slice(i, length), length);
	}

	public void Reset()
	{
		_internalBlockCrypto.Reset();
		_index = 0;
		_counterV = _iCounter;
	}

	public void Dispose()
	{
		_internalBlockCrypto.Dispose();

		GC.SuppressFinalize(this);
	}
}
