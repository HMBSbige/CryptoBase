namespace CryptoBase.Ciphers.Modes;

/// <summary>
/// Provides CTR mode with a big-endian 128-bit counter.
/// </summary>
/// <remarks>CTR does not authenticate ciphertext.</remarks>
/// <typeparam name="TBlockCipher">The block cipher type.</typeparam>
public sealed class CtrMode128<TBlockCipher> : IStreamCipher
	where TBlockCipher : IBlockEncryptor<TBlockCipher>
{
	private const int BlockSize = 16;
	private readonly TBlockCipher _blockCipher;
	private Vector128<byte> _counter;
	private Vector128<byte> _keyStream;
	private int _index;

	private CtrMode128(TBlockCipher blockCipher, ReadOnlySpan<byte> initialCounter)
	{
		_blockCipher = blockCipher;
		_counter = Vector128.LoadUnsafe(ref initialCounter.GetReference());
	}

	/// <summary>Creates a keyed CTR stream with the specified initial counter.</summary>
	/// <param name="key">The block cipher key.</param>
	/// <param name="initialCounter">The initial 16-byte big-endian counter block.</param>
	public static CtrMode128<TBlockCipher> Create(scoped ReadOnlySpan<byte> key, scoped ReadOnlySpan<byte> initialCounter)
	{
		ArgumentOutOfRangeException.ThrowIfNotEqual(TBlockCipher.BlockSize, BlockSize);
		ArgumentOutOfRangeException.ThrowIfNotEqual(initialCounter.Length, BlockSize, nameof(initialCounter));
		TBlockCipher cipher = TBlockCipher.Create(key);

		try
		{
			return new CtrMode128<TBlockCipher>(cipher, initialCounter);
		}
		catch
		{
			cipher.Dispose();
			throw;
		}
	}

	/// <inheritdoc />
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public void Xor(scoped ReadOnlySpan<byte> source, scoped Span<byte> destination)
	{
		CipherBufferGuard.Output(source, destination);

		int offset = 0;
		int left = source.Length;

		if (_index is not 0 && left > 0)
		{
			int n = Math.Min(BlockSize - _index, left);
			FastUtils.XorLess16(_keyStream.AsSpan().Slice(_index), source, destination, n);
			_index = _index + n & BlockSize - 1;
			offset += n;
			left -= n;
		}

		if (left > BlockSize)
		{
			int processed = CtrBlocks<TBlockCipher, CtrIncrementer128>.XorBlocks(_blockCipher, ref _counter, source.Slice(offset), destination.Slice(offset));
			offset += processed;
			left -= processed;
		}

		if (left > 0)
		{
			_keyStream = CtrBlocks<TBlockCipher, CtrIncrementer128>.EncryptCounter(_blockCipher, ref _counter);

			if (left is BlockSize)
			{
				(Vector128.LoadUnsafe(ref source.GetReference(), (nuint)offset) ^ _keyStream).StoreUnsafe(ref destination.GetReference(), (nuint)offset);
			}
			else
			{
				FastUtils.XorLess16(_keyStream.AsSpan(), source.Slice(offset), destination.Slice(offset), left);
			}

			_index = left & BlockSize - 1;
		}
	}

	/// <inheritdoc />
	public void Dispose()
	{
		_counter.ZeroMemory();
		_keyStream.ZeroMemory();
		_index = 0;
		_blockCipher.Dispose();
	}
}
