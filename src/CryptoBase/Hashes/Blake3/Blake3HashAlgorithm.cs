using System.Buffers;

namespace CryptoBase.Hashes.Blake3;

/// <summary>
/// Provides BLAKE3 hashing in its hash, keyed hash and key derivation modes, with extendable output and optional multithreading.
/// </summary>
/// <remarks>
/// <para>
/// The output is a stream of up to 2^64 bytes: a destination of any length receives its start, the default 32-byte length gives the standard hash, and a shorter output is a prefix of every longer one. A position reads the stream from any byte, so output can be produced in pieces or in parallel.
/// </para>
/// <para>
/// Generic code, such as the stream extensions of the CryptoBase.IO package, takes the hasher as an <see cref="IHashAlgorithm{TSelf}" />, whose members give the output the fixed length of any other hash: they write its first <see cref="HashLength" /> bytes, the standard hash in the hash mode, and return that length, whereas the public methods fill their whole destination.
/// </para>
/// <para>
/// As an <see cref="IXof{TSelf}" />, the instance also reads the stream in pieces: the first nonempty <see cref="Read" /> ends the input, and each read continues where the previous one stopped. Until <see cref="Reset" />, appending and the methods that write the start of the output then throw <see cref="InvalidOperationException" />, whereas <see cref="GetCurrentHash(Span{byte}, ulong, int)" /> still reads from any position.
/// </para>
/// <para>
/// The calling thread and up to <c>maxDegreeOfParallelism - 1</c> thread pool threads hash long input as independent subtrees, and generate long output as independent blocks. The degree of parallelism never changes the result, and -1 removes the limit.
/// </para>
/// <para>
/// Calls to <see cref="GetCurrentHash(Span{byte})" /> and <see cref="GetCurrentHash(Span{byte}, ulong, int)" /> may run concurrently with one another; every other instance operation, <see cref="Read" /> included, requires exclusive access.
/// </para>
/// <para>
/// A reset in the keyed hash and key derivation modes erases the buffered input and the chaining values and output that the instance holds, so that only the key remains until disposal; copies left in registers, on thread stacks or behind a moving garbage collector are out of reach. Disposal erases the state, key included, and is idempotent; subsequent instance operations other than disposal throw <see cref="ObjectDisposedException" />.
/// </para>
/// </remarks>
public sealed class Blake3HashAlgorithm : IHashAlgorithm<Blake3HashAlgorithm>, IXof<Blake3HashAlgorithm>
{
	/// <summary>
	/// The key length of the keyed hash mode, in bytes.
	/// </summary>
	public const int KeyLengthInBytes = Blake3Constants.KeyLength;

	private const int HashSizeInBytes = Blake3Constants.OutLength;

	/// <summary>
	/// The default output length, in bytes.
	/// </summary>
	public static int HashLength => HashSizeInBytes;

	private Blake3State _state;

	// Rented by the first append, and by the first that may stack a chaining value, so that the instance stays small and short input stacks nothing.
	private byte[]? _buffer;
	private byte[]? _stack;

	// Creating the output hashes the buffered input, so reads share it until the input changes. A read creates it in a local before it publishes it, so concurrent reads, which publish equal outputs, never see part of one. The next append learns from it that a read came in between.
	private Blake3Output _output;
	private bool _hasOutput;

	private bool _usedOutput;

	// A read in group mode hashes up to a group side by side, in about the time chunk mode takes to compress a group divided by the degree of the tree kernel block by block, and hashes the buffered input again later; chunk mode wins until reads come 3/2 times that far apart, or 5/2 times with Blake3Vector128x2, against which scalar compression keeps up better. A field, which the JIT takes as a constant, spares every append in chunk mode a call and a division.
	private static readonly int ChunkModeInterval = (Blake3Tree.Kernel is Blake3TreeKernel.Vector128x2 ? 5 : 3) * Blake3State.GroupLength / (2 * Blake3Tree.Degree);

	private bool _chunkMode;
	private ulong _readStart;
	private ulong _readEnd;

	// A read that ends the stream leaves the position at 2^64, so it needs more than 64 bits. Tests set it to read near the end of the stream.
	internal UInt128 ReadPosition { get; set; }

	private bool _reading;
	private bool _disposed;

	private Blake3HashAlgorithm()
	{
	}

	private static UInt128 OutputStreamLength => new(1, 0);

	/// <summary>
	/// Creates an instance in the hash mode.
	/// </summary>
	/// <returns>A new initialized instance.</returns>
	public static Blake3HashAlgorithm Create()
	{
		Blake3HashAlgorithm hasher = new();
		hasher._state.Initialize(in Blake3Constants.IV, 0);
		return hasher;
	}

	/// <summary>
	/// Creates an instance in the keyed hash mode, which turns BLAKE3 into a message authentication code and pseudorandom function.
	/// </summary>
	/// <param name="key">The 32-byte key.</param>
	/// <returns>A new initialized instance.</returns>
	/// <exception cref="ArgumentOutOfRangeException"><paramref name="key" /> is not 32 bytes long.</exception>
	public static Blake3HashAlgorithm CreateKeyed(ReadOnlySpan<byte> key)
	{
		ArgumentOutOfRangeException.ThrowIfNotEqual(key.Length, KeyLengthInBytes, nameof(key));

		// The key goes straight into the state, which leaves no copy of it to erase.
		Blake3HashAlgorithm hasher = new();
		hasher._state.Initialize(in Unsafe.As<byte, InlineArray8<uint>>(ref MemoryMarshal.GetReference(key)), Blake3Flags.KeyedHash);
		return hasher;
	}

	/// <summary>
	/// Creates an instance in the key derivation mode, whose input is the key material.
	/// </summary>
	/// <remarks>The context should be hardcoded, globally unique and application-specific, such as <c>"example.com 2020-01-01 session tokens v1"u8</c>.</remarks>
	/// <param name="context">The context string, usually UTF-8 encoded.</param>
	/// <returns>A new initialized instance.</returns>
	[SkipLocalsInit]
	public static Blake3HashAlgorithm CreateDeriveKey(ReadOnlySpan<byte> context)
	{
		Blake3HashAlgorithm hasher = new();
		DeriveContextKey(context, out InlineArray8<uint> contextKey);
		hasher._state.Initialize(in contextKey, Blake3Flags.DeriveKeyMaterial);
		contextKey.ZeroMemory();
		return hasher;
	}

	/// <summary>
	/// Computes the hash of <paramref name="source" />.
	/// </summary>
	/// <remarks>The <see cref="IOneShotHashAlgorithm" /> member of the same name writes only the first <see cref="HashLength" /> bytes.</remarks>
	/// <param name="source">The data to hash.</param>
	/// <param name="destination">The buffer that receives the output; its length selects the output length.</param>
	/// <param name="maxDegreeOfParallelism">The maximum number of threads, the calling thread included, or -1 for no limit.</param>
	/// <exception cref="ArgumentOutOfRangeException"><paramref name="maxDegreeOfParallelism" /> is 0 or less than -1.</exception>
	public static void HashData(ReadOnlySpan<byte> source, Span<byte> destination, int maxDegreeOfParallelism = 1)
	{
		HashData(source, destination, maxDegreeOfParallelism, ThreadPoolHelperBudget.Shared);
	}

	// Lets tests supply a budget that grants no helper or fails to queue one.
	internal static void HashData(ReadOnlySpan<byte> source, Span<byte> destination, int maxDegreeOfParallelism, ThreadPoolHelperBudget budget)
	{
		ThreadPoolHelper.ThrowIfInvalidParallelism(maxDegreeOfParallelism);

		Blake3Tree.HashData(source, in Blake3Constants.IV, 0, destination, maxDegreeOfParallelism, budget);
	}

	static int IOneShotHashAlgorithm.HashData(ReadOnlySpan<byte> source, Span<byte> destination)
	{
		ArgumentOutOfRangeException.ThrowIfLessThan(destination.Length, HashSizeInBytes, nameof(destination));

		Blake3Tree.HashData(source, in Blake3Constants.IV, 0, destination.Slice(0, HashSizeInBytes), 1, ThreadPoolHelperBudget.Shared);
		return HashSizeInBytes;
	}

	static void IXof<Blake3HashAlgorithm>.HashData(ReadOnlySpan<byte> source, Span<byte> destination)
	{
		HashData(source, destination);
	}

	/// <summary>
	/// Computes the keyed hash of <paramref name="source" />.
	/// </summary>
	/// <param name="key">The 32-byte key.</param>
	/// <param name="source">The data to hash.</param>
	/// <param name="destination">The buffer that receives the output; its length selects the output length.</param>
	/// <param name="maxDegreeOfParallelism">The maximum number of threads, the calling thread included, or -1 for no limit.</param>
	/// <exception cref="ArgumentOutOfRangeException">
	/// <paramref name="key" /> is not 32 bytes long, or <paramref name="maxDegreeOfParallelism" /> is 0 or less than -1.
	/// </exception>
	public static void KeyedHashData(ReadOnlySpan<byte> key, ReadOnlySpan<byte> source, Span<byte> destination, int maxDegreeOfParallelism = 1)
	{
		ArgumentOutOfRangeException.ThrowIfNotEqual(key.Length, KeyLengthInBytes, nameof(key));
		ThreadPoolHelper.ThrowIfInvalidParallelism(maxDegreeOfParallelism);

		// Hashing reads the key where the caller keeps it, which leaves no copy of it to erase, and is done with it before it writes the destination.
		Blake3Tree.HashData(source, in Unsafe.As<byte, InlineArray8<uint>>(ref MemoryMarshal.GetReference(key)), Blake3Flags.KeyedHash, destination, maxDegreeOfParallelism, ThreadPoolHelperBudget.Shared);
	}

	/// <summary>
	/// Derives key material for <paramref name="context" /> from <paramref name="keyMaterial" />.
	/// </summary>
	/// <remarks>The context should be hardcoded, globally unique and application-specific, such as <c>"example.com 2020-01-01 session tokens v1"u8</c>.</remarks>
	/// <param name="context">The context string, usually UTF-8 encoded.</param>
	/// <param name="keyMaterial">The input key material.</param>
	/// <param name="destination">The buffer that receives the derived key; its length selects the key length.</param>
	/// <param name="maxDegreeOfParallelism">The maximum number of threads, the calling thread included, or -1 for no limit.</param>
	/// <exception cref="ArgumentOutOfRangeException"><paramref name="maxDegreeOfParallelism" /> is 0 or less than -1.</exception>
	[SkipLocalsInit]
	public static void DeriveKey(ReadOnlySpan<byte> context, ReadOnlySpan<byte> keyMaterial, Span<byte> destination, int maxDegreeOfParallelism = 1)
	{
		ThreadPoolHelper.ThrowIfInvalidParallelism(maxDegreeOfParallelism);

		DeriveContextKey(context, out InlineArray8<uint> contextKey);

		// Hashing in parallel may fail for lack of memory, and the context key is erased all the same.
		try
		{
			Blake3Tree.HashData(keyMaterial, in contextKey, Blake3Flags.DeriveKeyMaterial, destination, maxDegreeOfParallelism, ThreadPoolHelperBudget.Shared);
		}
		finally
		{
			contextKey.ZeroMemory();
		}
	}

	/// <summary>
	/// Appends <paramref name="source" /> to the current input.
	/// </summary>
	/// <param name="source">The data to append.</param>
	/// <exception cref="InvalidOperationException">The instance is reading; call <see cref="Reset" /> first.</exception>
	/// <exception cref="ObjectDisposedException">The instance has been disposed.</exception>
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public void Append(ReadOnlySpan<byte> source)
	{
		ObjectDisposedException.ThrowIf(_disposed, this);
		ThrowHelper.ThrowIfXofReading(_reading);

		if (_chunkMode)
		{
			AppendInChunkMode(source);
		}
		else if (_hasOutput || !_state.TryBuffer(source, _buffer))
		{
			AppendCore(source, 1, ThreadPoolHelperBudget.Shared);
		}
	}

	/// <summary>
	/// Appends <paramref name="source" /> to the current input, hashing long input on several threads.
	/// </summary>
	/// <param name="source">The data to append.</param>
	/// <param name="maxDegreeOfParallelism">The maximum number of threads, the calling thread included, or -1 for no limit.</param>
	/// <exception cref="ArgumentOutOfRangeException"><paramref name="maxDegreeOfParallelism" /> is 0 or less than -1.</exception>
	/// <exception cref="InvalidOperationException">The instance is reading; call <see cref="Reset" /> first.</exception>
	/// <exception cref="ObjectDisposedException">The instance has been disposed.</exception>
	public void Append(ReadOnlySpan<byte> source, int maxDegreeOfParallelism)
	{
		Append(source, maxDegreeOfParallelism, ThreadPoolHelperBudget.Shared);
	}

	internal void Append(ReadOnlySpan<byte> source, int maxDegreeOfParallelism, ThreadPoolHelperBudget budget)
	{
		ObjectDisposedException.ThrowIf(_disposed, this);
		ThreadPoolHelper.ThrowIfInvalidParallelism(maxDegreeOfParallelism);
		ThrowHelper.ThrowIfXofReading(_reading);

		AppendCore(source, maxDegreeOfParallelism, budget);
	}

	/// <summary>
	/// Writes the start of the output for the current input without changing the state.
	/// </summary>
	/// <remarks>The <see cref="IHashAlgorithm{TSelf}" /> member of the same name writes only the first <see cref="HashLength" /> bytes.</remarks>
	/// <param name="destination">The buffer that receives the output; its length selects the output length.</param>
	/// <exception cref="InvalidOperationException">The instance is reading; call <see cref="Reset" /> first.</exception>
	/// <exception cref="ObjectDisposedException">The instance has been disposed.</exception>
	public void GetCurrentHash(Span<byte> destination)
	{
		ObjectDisposedException.ThrowIf(_disposed, this);
		ThrowHelper.ThrowIfXofReading(_reading);
		Output.RootBytes(0, destination, 1, ThreadPoolHelperBudget.Shared);
	}

	/// <summary>
	/// Writes the output for the current input from byte <paramref name="position" /> onwards without changing the state.
	/// </summary>
	/// <remarks>Unlike the methods that write the start of the output, this one also works while the instance is reading, and leaves the read position unchanged.</remarks>
	/// <param name="destination">The buffer that receives the output.</param>
	/// <param name="position">The position in the output stream of the first byte to write.</param>
	/// <param name="maxDegreeOfParallelism">The maximum number of threads, the calling thread included, or -1 for no limit.</param>
	/// <exception cref="ArgumentOutOfRangeException">
	/// The output would end past byte 2^64 - 1 of the stream, or <paramref name="maxDegreeOfParallelism" /> is 0 or less than -1.
	/// </exception>
	/// <exception cref="ObjectDisposedException">The instance has been disposed.</exception>
	public void GetCurrentHash(Span<byte> destination, ulong position, int maxDegreeOfParallelism = 1)
	{
		GetCurrentHash(destination, position, maxDegreeOfParallelism, ThreadPoolHelperBudget.Shared);
	}

	internal void GetCurrentHash(Span<byte> destination, ulong position, int maxDegreeOfParallelism, ThreadPoolHelperBudget budget)
	{
		ObjectDisposedException.ThrowIf(_disposed, this);
		ArgumentOutOfRangeException.ThrowIfGreaterThan(position + (UInt128)(uint)destination.Length, OutputStreamLength, nameof(destination));
		ThreadPoolHelper.ThrowIfInvalidParallelism(maxDegreeOfParallelism);

		Output.RootBytes(position, destination, maxDegreeOfParallelism, budget);
	}

	/// <summary>
	/// Writes the next <c>destination.Length</c> bytes of the output stream for the current input.
	/// </summary>
	/// <remarks>
	/// The first nonempty read ends the input and starts at the beginning of the stream; each later read continues where the previous one stopped, until <see cref="Reset" />. An empty <paramref name="destination" /> leaves the state unchanged.
	/// </remarks>
	/// <param name="destination">The buffer that receives the output.</param>
	/// <exception cref="ArgumentOutOfRangeException">The output would end past byte 2^64 - 1 of the stream.</exception>
	/// <exception cref="ObjectDisposedException">The instance has been disposed.</exception>
	[SkipLocalsInit]
	public void Read(Span<byte> destination)
	{
		ObjectDisposedException.ThrowIf(_disposed, this);

		if (destination.IsEmpty)
		{
			return;
		}

		UInt128 end = ReadPosition + (uint)destination.Length;
		ArgumentOutOfRangeException.ThrowIfGreaterThan(end, OutputStreamLength, nameof(destination));

		Output.RootBytes((ulong)ReadPosition, destination, 1, ThreadPoolHelperBudget.Shared);
		ReadPosition = end;
		_reading = true;
	}

	int IHashAlgorithm<Blake3HashAlgorithm>.GetCurrentHash(Span<byte> destination)
	{
		ObjectDisposedException.ThrowIf(_disposed, this);
		ArgumentOutOfRangeException.ThrowIfLessThan(destination.Length, HashSizeInBytes, nameof(destination));

		GetCurrentHash(destination.Slice(0, HashSizeInBytes));
		return HashSizeInBytes;
	}

	/// <summary>
	/// Writes the start of the output for the current input, then resets the state.
	/// </summary>
	/// <remarks>
	/// <para>
	/// In the keyed hash and key derivation modes, the reset erases the buffered input and the chaining values and output that the instance holds; the key remains until disposal.
	/// </para>
	/// <para>The <see cref="IHashAlgorithm{TSelf}" /> member of the same name writes only the first <see cref="HashLength" /> bytes.</para>
	/// </remarks>
	/// <param name="destination">The buffer that receives the output; its length selects the output length.</param>
	/// <exception cref="InvalidOperationException">The instance is reading; call <see cref="Reset" /> first.</exception>
	/// <exception cref="ObjectDisposedException">The instance has been disposed.</exception>
	[SkipLocalsInit]
	public void GetHashAndReset(Span<byte> destination)
	{
		ObjectDisposedException.ThrowIf(_disposed, this);
		ThrowHelper.ThrowIfXofReading(_reading);

		if (Volatile.Read(ref _hasOutput))
		{
			_output.RootBytes(0, destination, 1, ThreadPoolHelperBudget.Shared);
		}
		else
		{
			_state.CreateOutput(_buffer, _stack, out Blake3Output output);
			output.RootBytes(0, destination, 1, ThreadPoolHelperBudget.Shared);

			if (_state.IsSecret)
			{
				output.ZeroMemory();
			}
		}

		ResetState();
	}

	int IHashAlgorithm<Blake3HashAlgorithm>.GetHashAndReset(Span<byte> destination)
	{
		ObjectDisposedException.ThrowIf(_disposed, this);
		ArgumentOutOfRangeException.ThrowIfLessThan(destination.Length, HashSizeInBytes, nameof(destination));

		GetHashAndReset(destination.Slice(0, HashSizeInBytes));
		return HashSizeInBytes;
	}

	/// <summary>
	/// Resets the state, discarding the current input and leaving the reading state while keeping the mode and key.
	/// </summary>
	/// <remarks>In the keyed hash and key derivation modes, the reset erases the buffered input and the chaining values and output that the instance holds; the key remains until disposal.</remarks>
	/// <exception cref="ObjectDisposedException">The instance has been disposed.</exception>
	public void Reset()
	{
		ObjectDisposedException.ThrowIf(_disposed, this);
		ResetState();
	}

	/// <summary>
	/// Creates an independent copy of the current state.
	/// </summary>
	/// <returns>A new instance that continues from the current input or read position.</returns>
	/// <exception cref="ObjectDisposedException">The instance has been disposed.</exception>
	public Blake3HashAlgorithm Clone()
	{
		ObjectDisposedException.ThrowIf(_disposed, this);

		Blake3HashAlgorithm clone = new()
		{
			_state = _state,
			_chunkMode = _chunkMode,
			_readStart = _readStart,
			_readEnd = _readEnd,
			ReadPosition = ReadPosition,
			_reading = _reading
		};

		// Renting may fail for lack of memory; the caller then never receives the clone, so disposal erases what it has copied.
		try
		{
			clone._buffer = RentCopy(_buffer, _state.BufferLength);
			clone._stack = RentCopy(_stack, _state.StackLength);
			return clone;
		}
		catch
		{
			clone.Dispose();
			throw;
		}
	}

	/// <inheritdoc />
	public void Dispose()
	{
		if (_disposed)
		{
			return;
		}

		Return(ref _buffer, _state.UsedBufferLength);
		Return(ref _stack, _state.UsedStackLength);
		_state.ZeroMemory();
		_output.ZeroMemory();
		_disposed = true;
	}

	private Span<byte> Stack => (_stack ??= ArrayPool<byte>.Shared.Rent(Blake3State.MaxStackLength)).AsSpan(0, Blake3State.MaxStackLength);

	private bool PastChunkModeInterval
	{
		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		get => _state.InputLength - _readStart > (uint)ChunkModeInterval;
	}

	[SkipLocalsInit]
	private ref readonly Blake3Output Output
	{
		get
		{
			if (!Volatile.Read(ref _hasOutput))
			{
				_state.CreateOutput(_buffer, _stack, out Blake3Output output);
				_output = output;
				_usedOutput = true;
				Volatile.Write(ref _hasOutput, true);

				if (_state.IsSecret)
				{
					output.ZeroMemory();
				}
			}

			return ref _output;
		}
	}

	// The buffer is a group, so that short appends fill every lane of the widest kernel. A read hashes the buffered input, though, so reads that come often would hash it over and over; chunk mode buffers a chunk instead and compresses its blocks as they fill, so that a read compresses at most one.
	[MethodImpl(MethodImplOptions.NoInlining)]
	private void AppendCore(ReadOnlySpan<byte> source, int maxDegreeOfParallelism, ThreadPoolHelperBudget budget)
	{
		if (source.IsEmpty)
		{
			return;
		}

		_buffer ??= ArrayPool<byte>.Shared.Rent(Blake3State.GroupLength);
		Span<byte> buffer = _buffer.AsSpan(0, Blake3State.GroupLength);
		bool followsRead = _hasOutput;

		if (followsRead)
		{
			ChooseModeAfterRead(buffer);
			_hasOutput = false;
		}
		else if (_chunkMode && PastChunkModeInterval)
		{
			_chunkMode = false;
		}

		if (_chunkMode)
		{
			if (!_state.TryAppendToChunk(source, buffer))
			{
				_state.AppendToChunk(source, maxDegreeOfParallelism, budget, buffer, Stack);
			}
		}
		else if (!_state.TryBuffer(source, buffer))
		{
			_state.Append(source, maxDegreeOfParallelism, budget, buffer, Stack);
		}

		if (followsRead)
		{
			_readEnd = _state.InputLength;
		}
	}

	[MethodImpl(MethodImplOptions.NoInlining)]
	private void AppendInChunkMode(ReadOnlySpan<byte> source)
	{
		if (_hasOutput || PastChunkModeInterval || !_state.TryAppendToChunk(source, _buffer))
		{
			AppendCore(source, 1, ThreadPoolHelperBudget.Shared);
		}
	}

	// Shrinking the buffer may rent the stack, which may fail for lack of memory, so the mode changes only afterwards: chunk mode cannot take a buffer longer than a chunk.
	private void ChooseModeAfterRead(Span<byte> buffer)
	{
		ulong inputLength = _state.InputLength;
		bool chunkMode = inputLength == _readEnd || !PastChunkModeInterval;

		if (chunkMode && _state.BufferLength > Blake3Constants.ChunkLength)
		{
			_state.ShrinkBuffer(buffer, Stack);
		}

		_chunkMode = chunkMode;
		_readStart = inputLength;
	}

	private void ResetState()
	{
		// Erasing skips what the input has left untouched, the output included unless a read created it.
		if (_state.IsSecret)
		{
			_state.EraseAndReset(_buffer, _stack);

			if (_usedOutput)
			{
				_output.ZeroMemory();
			}
		}
		else
		{
			_state.Reset();
		}

		_hasOutput = false;
		_usedOutput = false;
		_chunkMode = false;
		_readStart = 0;
		_readEnd = 0;
		ReadPosition = 0;
		_reading = false;
	}

	private static byte[]? RentCopy(byte[]? array, int length)
	{
		if (array is null)
		{
			return null;
		}

		byte[] copy = ArrayPool<byte>.Shared.Rent(array.Length);
		array.AsSpan(0, length).CopyTo(copy);
		return copy;
	}

	private static void Return(ref byte[]? array, int usedLength)
	{
		if (array is null)
		{
			return;
		}

		array.AsSpan(0, usedLength).ZeroMemory();
		ArrayPool<byte>.Shared.Return(array);
		array = null;
	}

	// Hashes straight into the caller's variable, so that erasing it leaves no copy of the context key behind.
	private static void DeriveContextKey(ReadOnlySpan<byte> context, out InlineArray8<uint> contextKey)
	{
		Unsafe.SkipInit(out contextKey);
		Blake3Tree.HashData(context, in Blake3Constants.IV, Blake3Flags.DeriveKeyContext, contextKey.AsSpan(), 1, ThreadPoolHelperBudget.Shared);
	}
}
