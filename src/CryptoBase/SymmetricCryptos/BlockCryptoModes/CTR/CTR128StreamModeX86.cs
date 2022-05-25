using CryptoBase.Abstractions.SymmetricCryptos;
using System.Buffers;
using System.Runtime.CompilerServices;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.X86;

namespace CryptoBase.SymmetricCryptos.BlockCryptoModes.CTR;

public class CTR128StreamModeX86 : IStreamBlockCryptoMode
{
	public string Name => InternalBlockCrypto.Name + @"-CTR";

	public IBlockCrypto InternalBlockCrypto { get; init; }

	public ReadOnlyMemory<byte> Iv { get; init; }

	private readonly byte[] _counter;
	private readonly byte[] _keyStream;
	private readonly Vector128<byte> _iCounter;
	private Vector128<byte> _counterV;

	private int _index;

	private const int BlockSize = 16;

	public unsafe CTR128StreamModeX86(IBlockCrypto crypto, ReadOnlySpan<byte> iv)
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

		_counter = ArrayPool<byte>.Shared.Rent(BlockSize);
		_keyStream = ArrayPool<byte>.Shared.Rent(BlockSize);

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

			int r = BlockSize - _index;
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
		Span<byte> c = _counter.AsSpan(0, BlockSize);

		fixed (byte* p = c)
		{
			Sse2.Store(p, _counterV.ReverseEndianness128());
		}

		InternalBlockCrypto.Encrypt(c, _keyStream);

		_counterV = _counterV.Inc128Le();
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

		ArrayPool<byte>.Shared.Return(_counter);
		ArrayPool<byte>.Shared.Return(_keyStream);

		GC.SuppressFinalize(this);
	}
}
