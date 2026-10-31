using CryptoBase.IO.Chunked;
using CryptoBase.IO.Storage;

namespace CryptoBase.IO;

/// <summary>
/// Provides authenticated positional reads of a message encrypted with chunked authenticated encryption, such as Cobblestone.
/// </summary>
/// <typeparam name="TCipher">The chunked cipher.</typeparam>
/// <remarks>
/// <para>
/// The storage holds the encrypted message from offset zero to its end. Creating an instance checks the header against the key and context and then authenticates the last chunk, which authenticates the message <see cref="Length" />; truncated or extended storage fails there. Each read then authenticates every chunk it touches before it returns any plaintext, so a read of chunks that are intact succeeds even if other chunks were modified or reordered.
/// </para>
/// <para>
/// The instance keeps the plaintext of the last chunk that a partial read touched. The storage must not change while the instance uses it; a chunk that changes fails authentication.
/// </para>
/// <para>
/// The instance owns the cipher of the message and disposes it; <c>leaveOpen</c> controls only the storage.
/// Instances are not thread-safe. For parallel reads of a file, create one instance per thread over the same handle with <c>leaveOpen: true</c>; instances over one stream share its position, so they must not read in parallel.
/// </para>
/// </remarks>
public sealed class ChunkedRandomAccess<TCipher> : IDisposable where TCipher : class, IChunkedCipher<TCipher>
{
	private readonly IPositionalStorage _storage;
	private readonly IDisposable _owner;
	private readonly TCipher _cipher;
	private readonly bool _leaveOpen;
	private readonly ChunkSizes _sizes;
	private readonly long _lastChunk;

	// An encrypted chunk as it is read, then the plaintext of the cached chunk once it is decrypted in place.
	private readonly byte[] _buffer;
	private long _cachedChunk = -1;
	private bool _disposed;

	private ChunkedRandomAccess(IPositionalStorage storage, IDisposable owner, TCipher cipher, byte[] buffer, long length, bool leaveOpen)
	{
		_storage = storage;
		_owner = owner;
		_cipher = cipher;
		_buffer = buffer;
		_leaveOpen = leaveOpen;
		Length = length;
		_sizes = ChunkLayout<TCipher>.Sizes;
		_lastChunk = length / _sizes.ChunkSize;
	}

	/// <summary>
	/// Gets the message length, in bytes, which was authenticated when the instance was created.
	/// </summary>
	public long Length { get; }

	internal static ChunkedRandomAccess<TCipher> Create(IPositionalStorage storage, IDisposable owner, ReadOnlySpan<byte> key, ReadOnlySpan<byte> context, bool leaveOpen)
	{
		ChunkLayout<TCipher>.Validate(key, nameof(key));
		long length = GetPlaintextLength(storage);
		byte[] buffer = AllocateBuffer();
		Span<byte> header = buffer.AsSpan(0, TCipher.HeaderSize);
		ReadExactly(storage, header, 0);
		ChunkedRandomAccess<TCipher> instance = new(storage, owner, TCipher.CreateDecryptor(key, context, header), buffer, length, leaveOpen);

		try
		{
			instance.LoadChunk(instance._lastChunk);
			return instance;
		}
		catch
		{
			instance.Release();
			throw;
		}
	}

	internal static Task<ChunkedRandomAccess<TCipher>> CreateAsync(IPositionalStorage storage, IDisposable owner, ReadOnlyMemory<byte> key, ReadOnlyMemory<byte> context, bool leaveOpen, CancellationToken cancellationToken)
	{
		ChunkLayout<TCipher>.Validate(key.Span, nameof(key));

		if (cancellationToken.IsCancellationRequested)
		{
			return Task.FromCanceled<ChunkedRandomAccess<TCipher>>(cancellationToken);
		}

		return CreateCoreAsync(storage, owner, key, context, leaveOpen, cancellationToken);
	}

	/// <summary>
	/// Authenticates, decrypts and reads plaintext starting at <paramref name="offset" />.
	/// </summary>
	/// <param name="buffer">The buffer that receives the plaintext.</param>
	/// <param name="offset">The message offset to read from.</param>
	/// <returns>The number of bytes read; fewer than requested only at the end of the message, and zero at or past it.</returns>
	/// <exception cref="ArgumentOutOfRangeException"><paramref name="offset" /> is negative.</exception>
	/// <exception cref="AuthenticationTagMismatchException">A chunk in the range was modified or reordered, or the storage has become shorter. Chunks before it may already be in <paramref name="buffer" />.</exception>
	/// <exception cref="ObjectDisposedException">The instance is disposed.</exception>
	public int Read(Span<byte> buffer, long offset)
	{
		int count = GetReadCount(buffer.Length, offset);
		buffer = buffer.Slice(0, count);

		while (!buffer.IsEmpty)
		{
			long index = Math.DivRem(offset, _sizes.ChunkSize, out long remainder);
			int chunkOffset = (int)remainder;
			int chunkLength = GetChunkLength(index);
			int transferred;

			if (IsWholeChunkRead(index, chunkOffset, chunkLength, buffer.Length))
			{
				ReadEncryptedChunk(index);
				DecryptChunk(index, buffer);
				transferred = chunkLength;
			}
			else
			{
				if (index != _cachedChunk)
				{
					LoadChunk(index);
				}

				transferred = CopyCached(chunkOffset, chunkLength, buffer);
			}

			buffer = buffer.Slice(transferred);
			offset += transferred;
		}

		return count;
	}

	/// <summary>
	/// Asynchronously authenticates, decrypts and reads plaintext starting at <paramref name="offset" />.
	/// </summary>
	/// <param name="buffer">The buffer that receives the plaintext.</param>
	/// <param name="offset">The message offset to read from.</param>
	/// <param name="cancellationToken">The token used to cancel the operation.</param>
	/// <returns>A value task whose result is the number of bytes read; fewer than requested only at the end of the message, and zero at or past it.</returns>
	/// <exception cref="ArgumentOutOfRangeException"><paramref name="offset" /> is negative.</exception>
	/// <exception cref="AuthenticationTagMismatchException">A chunk in the range was modified or reordered, or the storage has become shorter. Chunks before it may already be in <paramref name="buffer" />.</exception>
	/// <exception cref="ObjectDisposedException">The instance is disposed.</exception>
	public ValueTask<int> ReadAsync(Memory<byte> buffer, long offset, CancellationToken cancellationToken = default)
	{
		int count = GetReadCount(buffer.Length, offset);

		if (cancellationToken.IsCancellationRequested)
		{
			return ValueTask.FromCanceled<int>(cancellationToken);
		}

		buffer = buffer.Slice(0, count);

		// A read within the cached chunk needs no I/O, so it completes synchronously.
		if (TryReadCached(buffer.Span, offset))
		{
			return ValueTask.FromResult(count);
		}

		return ReadCoreAsync(buffer, offset, cancellationToken);
	}

	/// <summary>
	/// Erases the cached plaintext and disposes the cipher and, unless <c>leaveOpen</c> was set, the storage.
	/// </summary>
	public void Dispose()
	{
		if (_disposed)
		{
			return;
		}

		Release();

		if (!_leaveOpen)
		{
			_owner.Dispose();
		}
	}

	private static async Task<ChunkedRandomAccess<TCipher>> CreateCoreAsync(IPositionalStorage storage, IDisposable owner, ReadOnlyMemory<byte> key, ReadOnlyMemory<byte> context, bool leaveOpen, CancellationToken cancellationToken)
	{
		long length = GetPlaintextLength(storage);
		byte[] buffer = AllocateBuffer();
		Memory<byte> header = buffer.AsMemory(0, TCipher.HeaderSize);
		await ReadExactlyAsync(storage, header, 0, cancellationToken).ConfigureAwait(false);
		ChunkedRandomAccess<TCipher> instance = new(storage, owner, TCipher.CreateDecryptor(key.Span, context.Span, header.Span), buffer, length, leaveOpen);

		try
		{
			await instance.LoadChunkAsync(instance._lastChunk, cancellationToken).ConfigureAwait(false);
			return instance;
		}
		catch
		{
			instance.Release();
			throw;
		}
	}

	private async ValueTask<int> ReadCoreAsync(Memory<byte> buffer, long offset, CancellationToken cancellationToken)
	{
		int count = buffer.Length;

		while (!buffer.IsEmpty)
		{
			long index = Math.DivRem(offset, _sizes.ChunkSize, out long remainder);
			int chunkOffset = (int)remainder;
			int chunkLength = GetChunkLength(index);
			int transferred;

			if (IsWholeChunkRead(index, chunkOffset, chunkLength, buffer.Length))
			{
				await ReadEncryptedChunkAsync(index, cancellationToken).ConfigureAwait(false);
				DecryptChunk(index, buffer.Span);
				transferred = chunkLength;
			}
			else
			{
				if (index != _cachedChunk)
				{
					await LoadChunkAsync(index, cancellationToken).ConfigureAwait(false);
				}

				transferred = CopyCached(chunkOffset, chunkLength, buffer.Span);
			}

			buffer = buffer.Slice(transferred);
			offset += transferred;
		}

		return count;
	}

	/// <summary>
	/// Validates a read and returns how many of <paramref name="requested" /> bytes exist at <paramref name="offset" />.
	/// </summary>
	private int GetReadCount(int requested, long offset)
	{
		ObjectDisposedException.ThrowIf(_disposed, this);
		ArgumentOutOfRangeException.ThrowIfNegative(offset);

		return offset >= Length ? 0 : (int)Math.Min(requested, Length - offset);
	}

	/// <summary>
	/// Gets whether a read decrypts the whole chunk numbered <paramref name="index" /> straight into the caller's buffer, which it does when the chunk is not cached and the read covers it.
	/// </summary>
	private bool IsWholeChunkRead(long index, int chunkOffset, int chunkLength, int remaining)
	{
		return index != _cachedChunk && chunkOffset is 0 && remaining >= chunkLength;
	}

	private int GetChunkLength(long index)
	{
		return index == _lastChunk ? (int)(Length - index * _sizes.ChunkSize) : _sizes.ChunkSize;
	}

	/// <summary>
	/// Reads the encrypted chunk numbered <paramref name="index" /> into the buffer, which drops the cached chunk.
	/// </summary>
	private void ReadEncryptedChunk(long index)
	{
		_cachedChunk = -1;
		ReadExactly(_storage, _buffer.AsSpan(0, GetChunkLength(index) + _sizes.TagSize), _sizes.GetChunkOffset(index));
	}

	/// <inheritdoc cref="ReadEncryptedChunk" />
	private ValueTask ReadEncryptedChunkAsync(long index, CancellationToken cancellationToken)
	{
		_cachedChunk = -1;
		return ReadExactlyAsync(_storage, _buffer.AsMemory(0, GetChunkLength(index) + _sizes.TagSize), _sizes.GetChunkOffset(index), cancellationToken);
	}

	private void LoadChunk(long index)
	{
		ReadEncryptedChunk(index);
		DecryptChunk(index, _buffer);
		_cachedChunk = index;
	}

	private async ValueTask LoadChunkAsync(long index, CancellationToken cancellationToken)
	{
		await ReadEncryptedChunkAsync(index, cancellationToken).ConfigureAwait(false);
		DecryptChunk(index, _buffer);
		_cachedChunk = index;
	}

	/// <summary>
	/// Authenticates the encrypted chunk numbered <paramref name="index" /> in the buffer and decrypts it into <paramref name="destination" />, which may be the buffer itself.
	/// </summary>
	private void DecryptChunk(long index, Span<byte> destination)
	{
		if (!_cipher.TryDecryptChunk(index, _buffer.AsSpan(0, GetChunkLength(index) + _sizes.TagSize), destination))
		{
			ChunkLayout<TCipher>.Throw(ChunkFailure.ChunkMismatch);
		}
	}

	private int CopyCached(int chunkOffset, int chunkLength, Span<byte> destination)
	{
		int length = Math.Min(chunkLength - chunkOffset, destination.Length);
		_buffer.AsSpan(chunkOffset, length).CopyTo(destination);
		return length;
	}

	/// <summary>
	/// Fills <paramref name="destination" /> from the cached chunk if the read lies within it, or fails without copying.
	/// </summary>
	private bool TryReadCached(Span<byte> destination, long offset)
	{
		long index = Math.DivRem(offset, _sizes.ChunkSize, out long chunkOffset);

		if (index != _cachedChunk || chunkOffset + destination.Length > GetChunkLength(index))
		{
			return false;
		}

		_buffer.AsSpan((int)chunkOffset, destination.Length).CopyTo(destination);
		return true;
	}

	private void Release()
	{
		_disposed = true;
		_cachedChunk = -1;
		CryptographicOperations.ZeroMemory(_buffer);
		_cipher.Dispose();
	}

	private static long GetPlaintextLength(IPositionalStorage storage)
	{
		if (!ChunkLayout<TCipher>.TryGetPlaintextLength(storage.GetLength(), out long length))
		{
			ChunkLayout<TCipher>.Throw(ChunkFailure.Truncated);
		}

		return length;
	}

	private static void ReadExactly(IPositionalStorage storage, Span<byte> buffer, long offset)
	{
		if (!storage.TryReadExactly(buffer, offset))
		{
			ChunkLayout<TCipher>.Throw(ChunkFailure.Truncated);
		}
	}

	private static async ValueTask ReadExactlyAsync(IPositionalStorage storage, Memory<byte> buffer, long offset, CancellationToken cancellationToken)
	{
		if (!await storage.TryReadExactlyAsync(buffer, offset, cancellationToken).ConfigureAwait(false))
		{
			ChunkLayout<TCipher>.Throw(ChunkFailure.Truncated);
		}
	}

	private static byte[] AllocateBuffer()
	{
		return GC.AllocateUninitializedArray<byte>(Math.Max(TCipher.HeaderSize, ChunkLayout<TCipher>.EncryptedChunkSize));
	}
}
