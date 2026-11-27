using CryptoBase.Ciphers.Modes.Ctr;

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
	// Not readonly: a readonly field would make Dispose run on a defensive copy when TBlockCipher is a struct.
	private TBlockCipher _blockCipher;
	private CtrStreamState _state;
	private bool _disposed;

	private CtrMode128(TBlockCipher blockCipher, ReadOnlySpan<byte> initialCounter)
	{
		_blockCipher = blockCipher;
		_state.Counter = Vector128.LoadUnsafe(ref MemoryMarshal.GetReference(initialCounter));
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

	/// <summary>Restarts the keystream from a new initial counter and keeps the expanded key.</summary>
	/// <remarks>Discards any unused keystream bytes from a partial block, so the next <see cref="Xor" /> call starts at a block boundary.</remarks>
	/// <param name="initialCounter">The new 16-byte big-endian counter block.</param>
	public void Reset(scoped ReadOnlySpan<byte> initialCounter)
	{
		ObjectDisposedException.ThrowIf(_disposed, this);
		ArgumentOutOfRangeException.ThrowIfNotEqual(initialCounter.Length, BlockSize, nameof(initialCounter));

		_state.Counter = Vector128.LoadUnsafe(ref MemoryMarshal.GetReference(initialCounter));
		_state.KeyStream.ZeroMemory();
		_state.Index = 0;
	}

	/// <inheritdoc />
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public void Xor(scoped ReadOnlySpan<byte> source, scoped Span<byte> destination)
	{
		ObjectDisposedException.ThrowIf(_disposed, this);
		CipherBufferGuard.Output(source, destination);

		int offset = 0;
		int left = source.Length;

		if (_state.Index is not 0 && left > 0)
		{
			int n = Math.Min(BlockSize - _state.Index, left);
			FastUtils.XorLess16(_state.KeyStream.AsSpan().Slice(_state.Index), source, destination, n);
			_state.Index = _state.Index + n & BlockSize - 1;
			offset += n;
			left -= n;
		}

		if (left > BlockSize)
		{
			if (BlockModeDispatch.TryXorCtrShort<TBlockCipher, CtrIncrementer128>(_blockCipher, ref _state, source, destination, offset))
			{
				return;
			}

			int processed = BlockModeDispatch.XorCtr<TBlockCipher, CtrIncrementer128>(_blockCipher, ref _state.Counter, source.Slice(offset), destination.Slice(offset));
			offset += processed;
			left -= processed;
		}

		if (left > BlockSize)
		{
			int processed = CtrBlocks<TBlockCipher, CtrIncrementer128>.XorBlocks(_blockCipher, ref _state.Counter, source.Slice(offset), destination.Slice(offset));
			offset += processed;
			left -= processed;
		}

		if (left > 0)
		{
			// Assigning the field only after the call keeps the address of _state from living across it.
			Vector128<byte> keyStream = CtrBlocks<TBlockCipher, CtrIncrementer128>.EncryptCounter(_blockCipher, ref _state.Counter);
			_state.KeyStream = keyStream;

			if (left is BlockSize)
			{
				(Vector128.LoadUnsafe(ref MemoryMarshal.GetReference(source), (nuint)offset) ^ keyStream).StoreUnsafe(ref MemoryMarshal.GetReference(destination), (nuint)offset);
			}
			else
			{
				FastUtils.XorLess16(_state.KeyStream.AsSpan(), source.Slice(offset), destination.Slice(offset), left);
			}

			_state.Index = left & BlockSize - 1;
		}
	}

	/// <inheritdoc />
	public void Dispose()
	{
		if (_disposed)
		{
			return;
		}

		_disposed = true;
		_state.ZeroMemory();
		_blockCipher.Dispose();
	}
}
