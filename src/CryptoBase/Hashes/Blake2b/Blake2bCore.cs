namespace CryptoBase.Hashes.Blake2b;

internal struct Blake2bCore
{
	internal const int BlockSizeInBytes = 128;
	internal const int MaxHashSizeInBytes = 64;

	internal const int Rounds = 12;

	internal const ulong IV0 = 0x6A09E667F3BCC908UL;
	internal const ulong IV1 = 0xBB67AE8584CAA73BUL;
	internal const ulong IV2 = 0x3C6EF372FE94F82BUL;
	internal const ulong IV3 = 0xA54FF53A5F1D36F1UL;
	internal const ulong IV4 = 0x510E527FADE682D1UL;
	internal const ulong IV5 = 0x9B05688C2B3E6C1FUL;
	internal const ulong IV6 = 0x1F83D9ABFB41BD6BUL;
	internal const ulong IV7 = 0x5BE0CD19137E2179UL;

	private const ulong ParameterBlock = 0x01010000UL;

	private InlineArray8<ulong> _state;
	private InlineArray8<ulong> _precompressedState;
	private UInt128 _counter;
	private int _bufferedLength;
	private bool _hasPrecompressedState;
	private InlineArray128<byte> _buffer;

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal void Initialize(int hashLength)
	{
		Debug.Assert(hashLength is > 0 and <= MaxHashSizeInBytes);

		// Reusing InitializeState here made GetHashAndReset slower.
		_state[0] = IV0 ^ ParameterBlock ^ (uint)hashLength;
		_state[1] = IV1;
		_state[2] = IV2;
		_state[3] = IV3;
		_state[4] = IV4;
		_state[5] = IV5;
		_state[6] = IV6;
		_state[7] = IV7;
		_counter = 0;
		_bufferedLength = 0;
		_hasPrecompressedState = false;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void InitializeState(out ulong state, int hashLength)
	{
		state = IV0 ^ ParameterBlock ^ (uint)hashLength;
		Unsafe.Add(ref state, 1) = IV1;
		Unsafe.Add(ref state, 2) = IV2;
		Unsafe.Add(ref state, 3) = IV3;
		Unsafe.Add(ref state, 4) = IV4;
		Unsafe.Add(ref state, 5) = IV5;
		Unsafe.Add(ref state, 6) = IV6;
		Unsafe.Add(ref state, 7) = IV7;
	}

	[SkipLocalsInit]
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static void HashData(ReadOnlySpan<byte> source, Span<byte> destination, int hashLength)
	{
		Debug.Assert(hashLength is > 0 and <= MaxHashSizeInBytes);
		Debug.Assert(destination.Length >= hashLength);

		Unsafe.SkipInit(out InlineArray8<ulong> stateBuffer);
		Span<ulong> state = stateBuffer;
		InitializeState(out state[0], hashLength);
		int sourceLength = source.Length;

		if (sourceLength > BlockSizeInBytes)
		{
			int blocksLength = sourceLength - 1 & ~(BlockSizeInBytes - 1);
			Compress(ref state[0], source.Slice(0, blocksLength), BlockSizeInBytes, 0);
			source = source.Slice(blocksLength);
		}

		if (source.Length is BlockSizeInBytes)
		{
			Compress(ref state[0], source, (uint)sourceLength, ulong.MaxValue);
		}
		else
		{
			Unsafe.SkipInit(out InlineArray128<byte> finalBuffer);
			Span<byte> finalBlock = finalBuffer;
			source.CopyTo(finalBlock);
			finalBlock.Slice(source.Length).Clear();
			Compress(ref state[0], finalBlock.AsReadOnlySpan(), (uint)sourceLength, ulong.MaxValue);
		}

		if (!BitConverter.IsLittleEndian)
		{
			BinaryPrimitives.ReverseEndianness(state, state);
		}

		MemoryMarshal.AsBytes(state).Slice(0, hashLength).CopyTo(destination);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal void Append(ReadOnlySpan<byte> source)
	{
		int bufferedLength = _bufferedLength;
		int bytesAvailable = BlockSizeInBytes - bufferedLength;

		// A full buffer stays pending until more input proves it is not the final block.
		if (source.Length <= bytesAvailable)
		{
			Span<byte> buffer = _buffer;
			source.CopyTo(buffer.Slice(bufferedLength));
			_bufferedLength = bufferedLength + source.Length;
			return;
		}

		AppendBlocks(source, bufferedLength, bytesAvailable);
	}

	private void AppendBlocks(ReadOnlySpan<byte> source, int bufferedLength, int bytesAvailable)
	{
		Debug.Assert(source.Length > bytesAvailable);

		Span<byte> buffer = _buffer;

		if (_hasPrecompressedState)
		{
			Debug.Assert(bufferedLength is BlockSizeInBytes);
			_state = _precompressedState;
			_counter += BlockSizeInBytes;
			_hasPrecompressedState = false;
		}
		else if (bufferedLength is not 0)
		{
			source.Slice(0, bytesAvailable).CopyTo(buffer.Slice(bufferedLength));
			source = source.Slice(bytesAvailable);
			CompressBlocks(buffer.AsReadOnlySpan());
		}

		int blocksLength = source.Length - 1 & ~(BlockSizeInBytes - 1);

		if (blocksLength is not 0)
		{
			CompressBlocks(source.Slice(0, blocksLength));
			source = source.Slice(blocksLength);
		}

		source.CopyTo(buffer);
		_bufferedLength = source.Length;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private void CompressBlocks(ReadOnlySpan<byte> blocks)
	{
		UInt128 counter = _counter + BlockSizeInBytes;
		_counter += (uint)blocks.Length;
		Compress(ref _state[0], blocks, counter, 0);
	}

	// Compresses a full pending buffer ahead of time, so copies of this state such as HMAC key seeds skip that compression when more input follows.
	internal void PrecompressBuffer()
	{
		if (_bufferedLength is not BlockSizeInBytes || _hasPrecompressedState)
		{
			return;
		}

		_precompressedState = _state;
		Compress(ref _precompressedState[0], _buffer, _counter + BlockSizeInBytes, 0);
		_hasPrecompressedState = true;
	}

	internal void Finalize(Span<byte> destination, int hashLength)
	{
		Debug.Assert(hashLength is > 0 and <= MaxHashSizeInBytes);
		Debug.Assert(destination.Length >= hashLength);

		Span<byte> buffer = _buffer;
		int bufferedLength = _bufferedLength;
		buffer.Slice(bufferedLength).Clear();
		Compress(ref _state[0], buffer.AsReadOnlySpan(), _counter + (uint)bufferedLength, ulong.MaxValue);

		Span<ulong> state = _state;

		if (!BitConverter.IsLittleEndian)
		{
			BinaryPrimitives.ReverseEndianness(state, state);
		}

		MemoryMarshal.AsBytes(state).Slice(0, hashLength).CopyTo(destination);
	}

	// Single-stream BLAKE2b is bound by the serial dependency chain of G, so vector kernels only win where vector integer additions and rotations take one cycle.
	// Zen 5 and ARM64 cores take two, so x64 Zen 5 and ARM64 use the scalar kernel.
	// 32-bit x86 keeps the vector kernels because it has no 64-bit general-purpose registers.
	private static readonly bool PreferScalar = X86Base.X64.IsSupported && CpuIdUtils.IsAmdZen5();

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void Compress(ref ulong state, ReadOnlySpan<byte> blocks, UInt128 counter, ulong finalFlag)
	{
		if (Blake2bVector256.IsSupported && !PreferScalar)
		{
			Blake2bVector256.Compress(ref state, blocks, counter, finalFlag);
			return;
		}

		if (Blake2bVector128.IsSupported && !PreferScalar)
		{
			Blake2bVector128.Compress(ref state, blocks, counter, finalFlag);
			return;
		}

		Blake2bScalar.Compress(ref state, blocks, counter, finalFlag);
	}
}
