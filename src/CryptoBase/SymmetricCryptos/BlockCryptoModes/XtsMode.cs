namespace CryptoBase.SymmetricCryptos.BlockCryptoModes;

public sealed class XtsMode : IBlockModeOneShot
{
	public string Name => _dataCrypto.Name + @"-XTS";

	public int BlockSize => 16;

	private readonly IBlockCrypto _dataCrypto;
	private readonly IBlockCrypto _tweakCrypto;
	private readonly bool _disposeCrypto;

	public XtsMode(IBlockCrypto dataCrypto, IBlockCrypto tweakCrypto, bool disposeCrypto = true)
	{
		ArgumentOutOfRangeException.ThrowIfNotEqual(dataCrypto.BlockSize, BlockSize, nameof(dataCrypto));
		ArgumentOutOfRangeException.ThrowIfNotEqual(tweakCrypto.BlockSize, BlockSize, nameof(tweakCrypto));

		_dataCrypto = dataCrypto;
		_tweakCrypto = tweakCrypto;
		_disposeCrypto = disposeCrypto;
	}

	[SkipLocalsInit]
	public void Encrypt(in ReadOnlySpan<byte> iv, in ReadOnlySpan<byte> source, in Span<byte> destination)
	{
		ArgumentOutOfRangeException.ThrowIfNotEqual(iv.Length, BlockSize, nameof(iv));
		ArgumentOutOfRangeException.ThrowIfLessThan(source.Length, BlockSize, nameof(source));
		ArgumentOutOfRangeException.ThrowIfLessThan(destination.Length, source.Length, nameof(destination));

		using CryptoBuffer<byte> cryptoBuffer = new(stackalloc byte[BlockSize]);
		Span<byte> tweak = cryptoBuffer.Span;
		_tweakCrypto.Encrypt(iv, tweak);

		int left = source.Length % BlockSize;
		int size = source.Length - left;

		using (CryptoBuffer<byte> buffer = new(size))
		{
			Span<byte> tweakBuffer = buffer.Span;

			for (int i = 0; i < size; i += BlockSize)
			{
				tweak.CopyTo(tweakBuffer.Slice(i));
				Gf128Mul(ref tweak);
			}

			FastUtils.Xor(source, tweakBuffer, destination, size);

			for (int i = 0; i < size; i += BlockSize)
			{
				Span<byte> block = destination.Slice(i, BlockSize);
				_dataCrypto.Encrypt(block, block);
			}

			FastUtils.Xor(destination, tweakBuffer, size);
		}

		if (left is not 0)
		{
			Span<byte> lastDSt = destination.Slice(size - BlockSize, BlockSize);

			lastDSt.Slice(0, left).CopyTo(destination.Slice(size));
			source.Slice(size).CopyTo(lastDSt);

			FastUtils.Xor16(lastDSt, tweak);
			_dataCrypto.Encrypt(lastDSt, lastDSt);
			FastUtils.Xor16(lastDSt, tweak);
		}
	}

	[SkipLocalsInit]
	public void Decrypt(in ReadOnlySpan<byte> iv, in ReadOnlySpan<byte> source, in Span<byte> destination)
	{
		ArgumentOutOfRangeException.ThrowIfNotEqual(iv.Length, BlockSize, nameof(iv));
		ArgumentOutOfRangeException.ThrowIfLessThan(source.Length, BlockSize, nameof(source));
		ArgumentOutOfRangeException.ThrowIfLessThan(destination.Length, source.Length, nameof(destination));

		using CryptoBuffer<byte> cryptoBuffer = new(stackalloc byte[BlockSize]);
		Span<byte> tweak = cryptoBuffer.Span;
		_tweakCrypto.Encrypt(iv, tweak);

		int left = source.Length % BlockSize;
		int size = source.Length - left - (BlockSize & (left | -left) >> 31);

		using (CryptoBuffer<byte> buffer = new(size))
		{
			Span<byte> tweakBuffer = buffer.Span;

			for (int i = 0; i < size; i += BlockSize)
			{
				tweak.CopyTo(tweakBuffer.Slice(i));
				Gf128Mul(ref tweak);
			}

			FastUtils.Xor(source, tweakBuffer, destination, size);

			for (int i = 0; i < size; i += BlockSize)
			{
				Span<byte> block = destination.Slice(i, BlockSize);
				_dataCrypto.Decrypt(block, block);
			}

			FastUtils.Xor(destination, tweakBuffer, size);
		}

		if (left is not 0)
		{
			using CryptoBuffer<byte> buffer = new(stackalloc byte[BlockSize]);
			Span<byte> finalTweak = buffer.Span;
			tweak.CopyTo(finalTweak);
			Gf128Mul(ref finalTweak);

			ReadOnlySpan<byte> lastSrc = source.Slice(size);
			Span<byte> lastDst = destination.Slice(size);

			FastUtils.Xor16(lastSrc, finalTweak, lastDst);
			_dataCrypto.Decrypt(lastDst, lastDst);
			FastUtils.Xor16(lastDst, finalTweak);

			lastDst.Slice(0, left).CopyTo(lastDst.Slice(BlockSize));
			lastSrc.Slice(BlockSize, left).CopyTo(lastDst);

			FastUtils.Xor16(lastDst, tweak);
			_dataCrypto.Decrypt(lastDst, lastDst);
			FastUtils.Xor16(lastDst, tweak);
		}
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void Gf128Mul(ref Span<byte> buffer)
	{
		ref byte ptr = ref buffer.GetReference();

		if (Sse2.IsSupported)
		{
			ref Vector128<byte> tweak = ref Unsafe.As<byte, Vector128<byte>>(ref ptr);

			Vector128<int> mask = Sse2.Shuffle(tweak.AsInt32(), 0b00_01_00_11) >> 31 & Vector128.Create(0x87, 1).AsInt32();

			Vector128<ulong> t = tweak.AsUInt64() << 1;

			tweak = t.AsByte() ^ mask.AsByte();
		}
		else
		{
			ref Int128 i = ref Unsafe.As<byte, Int128>(ref ptr);

			i = i << 1 ^ i >> 127 & 0x87;
		}
	}

	public static void GetIv(in Span<byte> iv, in UInt128 dataUnitSeqNumber)
	{
		BinaryPrimitives.WriteUInt128LittleEndian(iv, dataUnitSeqNumber);
	}

	public void Dispose()
	{
		if (_disposeCrypto)
		{
			_dataCrypto.Dispose();
			_tweakCrypto.Dispose();
		}
	}
}
