using System.Buffers;

namespace CryptoBase.Hashes.Blake3;

/// <summary>
/// Provides BLAKE3 hashing in its hash, keyed hash and key derivation modes, with extendable output and optional multithreading.
/// </summary>
/// <remarks>
/// <para>
/// The output is a stream of up to 2^64 bytes: a destination of any length receives its start, the default 32-byte length gives the standard hash,
/// and a shorter output is a prefix of every longer one. A position reads the stream from any byte, so output can be produced in pieces or in parallel.
/// </para>
/// <para>
/// Generic code, such as the stream extensions of <see cref="HashUtils" />, takes the hasher as an <see cref="IHashAlgorithm{TSelf}" />, whose members give
/// the output the fixed length of any other hash: they write its first <see cref="HashLength" /> bytes, the standard hash in the hash mode, and return
/// that length, whereas the public methods fill their whole destination.
/// </para>
/// <para>
/// The calling thread and up to <c>maxDegreeOfParallelism - 1</c> thread pool threads hash long input as independent subtrees, and generate long output as independent blocks.
/// The degree of parallelism never changes the result, and -1 removes the limit.
/// </para>
/// <para>
/// Reads through <see cref="GetCurrentHash(Span{byte})" /> and <see cref="GetCurrentHash(Span{byte}, ulong, int)" /> may run concurrently with one another;
/// every other instance operation requires exclusive access.
/// </para>
/// <para>
/// A reset in the keyed hash and key derivation modes erases the buffered input and the chaining values and output that the instance holds, so that only the key
/// remains until disposal; copies left in registers, on thread stacks or behind a moving garbage collector are out of reach. Disposal erases the state, key
/// included, and is idempotent; subsequent instance operations other than disposal throw <see cref="ObjectDisposedException" />.
/// </para>
/// </remarks>
public sealed class Blake3HashAlgorithm : IHashAlgorithm<Blake3HashAlgorithm>
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

	// Creating the output hashes the buffered input, so reads share it until the input changes. A read creates it in a local before it publishes it,
	// so concurrent reads, which publish equal outputs, never see part of one. The next append learns from it that a read came in between.
	private Blake3Output _output;
	private bool _hasOutput;

	private bool _usedOutput;

	// A read in group mode hashes up to a group side by side, in about the time chunk mode takes to compress a group divided by the degree of the tree kernel
	// block by block, and hashes the buffered input again later; chunk mode wins until reads come about 1.5 times that far apart on Zen 5 and Intel cores, and
	// about 2.5 times on Apple cores, whose scalar compression keeps up better with Blake3Vector128x2. A field, which the JIT takes as a constant, spares
	// every append in chunk mode a call and a division.
	private static readonly int ChunkModeInterval = (Blake3Tree.Kernel is Blake3TreeKernel.Vector128x2 ? 5 : 3) * Blake3State.GroupLength / (2 * Blake3Tree.Degree);

	private bool _chunkMode;
	private ulong _readStart;
	private ulong _readEnd;

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
	[SkipLocalsInit]
	public static Blake3HashAlgorithm CreateKeyed(ReadOnlySpan<byte> key)
	{
		ArgumentOutOfRangeException.ThrowIfNotEqual(key.Length, KeyLengthInBytes, nameof(key));

		// Allocating first leaves no copy of the key behind should allocation fail.
		Blake3HashAlgorithm hasher = new();
		InlineArray8<uint> keyWords = Blake3Words.Load(in MemoryMarshal.GetReference(key));
		hasher._state.Initialize(in keyWords, Blake3Flags.KeyedHash);
		keyWords.ZeroMemory();
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
		InlineArray8<uint> contextKey = DeriveContextKey(context);
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
	[SkipLocalsInit]
	public static void KeyedHashData(ReadOnlySpan<byte> key, ReadOnlySpan<byte> source, Span<byte> destination, int maxDegreeOfParallelism = 1)
	{
		ArgumentOutOfRangeException.ThrowIfNotEqual(key.Length, KeyLengthInBytes, nameof(key));
		ThreadPoolHelper.ThrowIfInvalidParallelism(maxDegreeOfParallelism);

		InlineArray8<uint> keyWords = Blake3Words.Load(in MemoryMarshal.GetReference(key));

		// Hashing in parallel may fail for lack of memory, and the copy of the key is erased all the same.
		try
		{
			Blake3Tree.HashData(source, in keyWords, Blake3Flags.KeyedHash, destination, maxDegreeOfParallelism, ThreadPoolHelperBudget.Shared);
		}
		finally
		{
			keyWords.ZeroMemory();
		}
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

		InlineArray8<uint> contextKey = DeriveContextKey(context);

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
	/// <exception cref="ObjectDisposedException">The instance has been disposed.</exception>
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public void Append(ReadOnlySpan<byte> source)
	{
		ObjectDisposedException.ThrowIf(_disposed, this);

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
	/// <exception cref="ObjectDisposedException">The instance has been disposed.</exception>
	public void Append(ReadOnlySpan<byte> source, int maxDegreeOfParallelism)
	{
		Append(source, maxDegreeOfParallelism, ThreadPoolHelperBudget.Shared);
	}

	internal void Append(ReadOnlySpan<byte> source, int maxDegreeOfParallelism, ThreadPoolHelperBudget budget)
	{
		ObjectDisposedException.ThrowIf(_disposed, this);
		ThreadPoolHelper.ThrowIfInvalidParallelism(maxDegreeOfParallelism);

		AppendCore(source, maxDegreeOfParallelism, budget);
	}

	/// <summary>
	/// Writes the start of the output for the current input without changing the state.
	/// </summary>
	/// <remarks>The <see cref="IHashAlgorithm{TSelf}" /> member of the same name writes only the first <see cref="HashLength" /> bytes.</remarks>
	/// <param name="destination">The buffer that receives the output; its length selects the output length.</param>
	/// <exception cref="ObjectDisposedException">The instance has been disposed.</exception>
	public void GetCurrentHash(Span<byte> destination)
	{
		ObjectDisposedException.ThrowIf(_disposed, this);
		Output.RootBytes(0, destination, 1, ThreadPoolHelperBudget.Shared);
	}

	/// <summary>
	/// Writes the output for the current input from byte <paramref name="position" /> onwards without changing the state.
	/// </summary>
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
	/// In the keyed hash and key derivation modes, the reset erases the buffered input and the chaining values and output that the instance holds; the key
	/// remains until disposal.
	/// </para>
	/// <para>The <see cref="IHashAlgorithm{TSelf}" /> member of the same name writes only the first <see cref="HashLength" /> bytes.</para>
	/// </remarks>
	/// <param name="destination">The buffer that receives the output; its length selects the output length.</param>
	/// <exception cref="ObjectDisposedException">The instance has been disposed.</exception>
	[SkipLocalsInit]
	public void GetHashAndReset(Span<byte> destination)
	{
		ObjectDisposedException.ThrowIf(_disposed, this);

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
	/// Resets the state, discarding the current input while keeping the mode and key.
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
	/// <returns>A new instance that continues from the current input.</returns>
	/// <exception cref="ObjectDisposedException">The instance has been disposed.</exception>
	public Blake3HashAlgorithm Clone()
	{
		ObjectDisposedException.ThrowIf(_disposed, this);

		Blake3HashAlgorithm clone = new()
		{
			_state = _state,
			_chunkMode = _chunkMode,
			_readStart = _readStart,
			_readEnd = _readEnd
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

	// The buffer is a group, so that short appends fill every lane of the widest kernel. A read hashes the buffered input, though, so reads that come often
	// would hash it over and over; chunk mode buffers a chunk instead and compresses its blocks as they fill, so that a read compresses at most one.
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

	// Shrinking the buffer may rent the stack, which may fail for lack of memory, so the mode changes only afterwards: chunk mode cannot take a buffer longer
	// than a chunk.
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
		// Erasing skips what the input has left untouched, the output included unless a read created it, which on 64-byte messages cuts the cost of a reset by
		// about two thirds.
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

	[SkipLocalsInit]
	private static InlineArray8<uint> DeriveContextKey(ReadOnlySpan<byte> context)
	{
		Unsafe.SkipInit(out InlineArray8<uint> contextKey);
		Span<uint> words = contextKey;
		Blake3Tree.HashData(context, in Blake3Constants.IV, Blake3Flags.DeriveKeyContext, MemoryMarshal.AsBytes(words), 1, ThreadPoolHelperBudget.Shared);

		if (!BitConverter.IsLittleEndian)
		{
			BinaryPrimitives.ReverseEndianness(words, words);
		}

		return contextKey;
	}
}
