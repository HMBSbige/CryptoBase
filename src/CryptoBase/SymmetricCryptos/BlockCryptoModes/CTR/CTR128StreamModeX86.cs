using CryptoBase.Abstractions.SymmetricCryptos;

namespace CryptoBase.SymmetricCryptos.BlockCryptoModes.CTR;

public class CTR128StreamModeX86 : IStreamBlockCryptoMode
{
	public string Name => InternalBlockCrypto.Name + @"-CTR";

	public IBlockCrypto InternalBlockCrypto { get; init; }

	public ReadOnlyMemory<byte> Iv { get; init; }

	private readonly Vector128<byte> _iCounter;
	private Vector128<byte> _counterV;

	private int _index;

	private const int BlockSize = 16;

	public CTR128StreamModeX86(IBlockCrypto crypto, ReadOnlySpan<byte> iv)
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

		_iCounter = FastUtils.CreateVector128Unsafe(iv).ReverseEndianness128();

		Reset();
	}

	public void Update(ReadOnlySpan<byte> source, Span<byte> destination)
	{
		if (destination.Length < source.Length)
		{
			throw new ArgumentException(string.Empty, nameof(destination));
		}

		int i = 0;
		int length = source.Length;

		Span<byte> stream = stackalloc byte[BlockSize];
		Span<byte> c = stackalloc byte[BlockSize];

		if (_index is not 0)
		{
			_counterV.ReverseEndianness128().CopyTo(c);
			InternalBlockCrypto.Encrypt(c, stream);

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
			InternalBlockCrypto.Encrypt(c, stream);
			_counterV = _counterV.Inc128Le();

			FastUtils.Xor(stream, source.Slice(i, BlockSize), destination.Slice(i, BlockSize), BlockSize);

			i += BlockSize;
			length -= BlockSize;
		}

		_index = length;
		_counterV.ReverseEndianness128().CopyTo(c);
		InternalBlockCrypto.Encrypt(c, stream);
		FastUtils.Xor(stream.Slice(0, length), source.Slice(i, length), destination.Slice(i, length), length);
	}

	public void Reset()
	{
		InternalBlockCrypto.Reset();
		_index = 0;
		_counterV = _iCounter;
	}

	public void Dispose()
	{
		InternalBlockCrypto.Dispose();

		GC.SuppressFinalize(this);
	}
}
