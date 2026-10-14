using CryptoBase.Hashes.Blake3;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using static CryptoBase.Tests.TestUtils;

namespace CryptoBase.Tests.Hashes.Blake3;

[SuppressMessage("ReSharper", "AccessToDisposedClosure")]
public class Blake3HashAlgorithmTest
{
	private const int OutputLength = 2 * 64 + 33;

	public static IEnumerable<int> TreeLengths => [0, 1, 1024, 1025, 2048, 2049, 3072, 3073, 4096, 4097, 5121, 8192, 8193, 16385, 31751, 65536, 65537, 132097];

	private static readonly int[] PieceLengths = [1, 63, 64, 65, 1023, 1024, 1025, 2047, 2048, 3000, 4096, 5000, 16384];

	private static readonly int[] HeadLengths = [1, 1023, 1024, 1025, 2048, 3072, 5000];

	public static IEnumerable<ulong> OutputPositions => [0, 1, 63, 64, 65, 1000, (1UL << 38) - 130, 1UL << 38, ulong.MaxValue - 4000];

	private static readonly int[] OutputLengths = [0, 1, 63, 64, 65, 33 * 64 + 7];

	[Test]
	[CombinedDataSources]
	public async Task IncrementalMatchesReference([MethodDataSource(nameof(TreeLengths))] int length, [MethodDataSource(typeof(Blake3TestUtils), nameof(Blake3TestUtils.Modes))] Blake3Mode mode)
	{
		byte[] source = CreateDeterministicSource(length);
		byte[] expected = Blake3TestUtils.ReferenceHash(mode, source, OutputLength);
		using Blake3HashAlgorithm hasher = Blake3TestUtils.CreateHasher(mode);

		await Assert.That(Blake3TestUtils.HashData(mode, source, OutputLength)).IsEquivalentTo(expected, CollectionOrdering.Matching);

		hasher.Append(source);
		await Blake3TestUtils.VerifyCurrentHash(hasher, expected);

		foreach (int pieceLength in PieceLengths)
		{
			hasher.Reset();
			HashAlgorithmTestUtils.AppendInPieces(hasher, source, pieceLength);
			await Blake3TestUtils.VerifyCurrentHash(hasher, expected);
		}

		foreach (int headLength in HeadLengths.Where(headLength => headLength < length))
		{
			hasher.Reset();
			hasher.Append(source.AsSpan(0, headLength));
			hasher.Append(source.AsSpan(headLength));
			await Blake3TestUtils.VerifyCurrentHash(hasher, expected);
		}

		hasher.Reset();
		HashAlgorithmTestUtils.AppendInPseudoRandomPieces(hasher, source, (uint)length, 5000);
		await Blake3TestUtils.VerifyCurrentHash(hasher, expected);
	}

	[Test]
	[CombinedDataSources]
	public async Task ExtendedOutputMatchesReference([Arguments(0, 65, 1025, 4097)] int inputLength, [MethodDataSource(nameof(OutputPositions))] ulong position)
	{
		byte[] source = CreateDeterministicSource(inputLength);

		foreach (Blake3Mode mode in Blake3TestUtils.Modes)
		{
			using Blake3HashAlgorithm hasher = Blake3TestUtils.CreateHasher(mode);
			hasher.Append(source);

			foreach (int length in OutputLengths)
			{
				byte[] expected = Blake3TestUtils.ReferenceHash(mode, source, length, position);
				byte[] destination = new byte[length + 1];
				PrepareDestination(destination);
				hasher.GetCurrentHash(destination.AsSpan(0, length), position);
				await AssertOutput(destination, expected);
			}
		}
	}

	[Test]
	public async Task LongOutputMatchesReference()
	{
		const int length = 1024 * 1024 + 13;
		byte[] source = CreateDeterministicSource(3000);
		byte[] expected = Blake3TestUtils.ReferenceHash(Blake3Mode.Hash, source, length, 7);
		using Blake3HashAlgorithm hasher = Blake3HashAlgorithm.Create();
		hasher.Append(source);
		byte[] destination = new byte[length + 1];

		PrepareDestination(destination);
		hasher.GetCurrentHash(destination.AsSpan(0, length), 7);
		await AssertOutput(destination, expected);
	}

	[Test]
	public async Task OutputStreamEndsAfterTwoToThe64Bytes()
	{
		byte[] source = "abc"u8.ToArray();
		byte[] expected = Blake3TestUtils.ReferenceHash(Blake3Mode.Hash, source, 65, ulong.MaxValue - 64);
		using Blake3HashAlgorithm hasher = Blake3HashAlgorithm.Create();
		hasher.Append(source);

		byte[] tail = new byte[65];
		hasher.GetCurrentHash(tail, ulong.MaxValue - 64);
		byte[] lastByte = new byte[1];
		hasher.GetCurrentHash(lastByte, ulong.MaxValue);
		hasher.GetCurrentHash(Span<byte>.Empty, ulong.MaxValue);

		byte[] destination = new byte[66];
		PrepareDestination(destination);

		using (Assert.Multiple())
		{
			await Assert.That(tail).IsEquivalentTo(expected, CollectionOrdering.Matching);
			await Assert.That(lastByte[0]).IsEqualTo(expected[^1]);
			await Assert.That(() => hasher.GetCurrentHash(destination.AsSpan(0, 2), ulong.MaxValue)).ThrowsExactly<ArgumentOutOfRangeException>().WithParameterName("destination");
			await Assert.That(() => hasher.GetCurrentHash(destination, ulong.MaxValue - 64)).ThrowsExactly<ArgumentOutOfRangeException>().WithParameterName("destination");
			await Assert.That(destination).All(static value => value is DestinationSentinel);
		}
	}

	[Test]
	[MethodDataSource(typeof(Blake3TestUtils), nameof(Blake3TestUtils.Modes))]
	public async Task LifecycleContract(Blake3Mode mode)
	{
		byte[] source = CreateDeterministicSource(3000);
		byte[] expected = Blake3TestUtils.ReferenceHash(mode, source, Blake3HashAlgorithm.HashLength);
		byte[] emptyExpected = Blake3TestUtils.ReferenceHash(mode, [], Blake3HashAlgorithm.HashLength);
		byte[] doubledExpected = Blake3TestUtils.ReferenceHash(mode, Concat(source, source), Blake3HashAlgorithm.HashLength);
		using Blake3HashAlgorithm hasher = Blake3TestUtils.CreateHasher(mode);

		await Blake3TestUtils.VerifyCurrentHash(hasher, emptyExpected);

		hasher.Append(source.AsSpan(0, 1000));
		hasher.Append(source.AsSpan(1000));
		await Blake3TestUtils.VerifyCurrentHash(hasher, expected);
		await Blake3TestUtils.VerifyCurrentHash(hasher, expected);

		using Blake3HashAlgorithm clone = hasher.Clone();
		hasher.Append(source);
		byte[] destination = new byte[Blake3HashAlgorithm.HashLength + 1];
		PrepareDestination(destination);
		hasher.GetHashAndReset(destination.AsSpan(0, Blake3HashAlgorithm.HashLength));
		await AssertOutput(destination, doubledExpected);
		await Blake3TestUtils.VerifyCurrentHash(hasher, emptyExpected);

		await Blake3TestUtils.VerifyCurrentHash(clone, expected);
		clone.Append(source);
		await Blake3TestUtils.VerifyCurrentHash(clone, doubledExpected);

		hasher.Append(source);
		await Blake3TestUtils.VerifyCurrentHash(hasher, expected);
		hasher.Reset();
		await Blake3TestUtils.VerifyCurrentHash(hasher, emptyExpected);
		hasher.Append(source);
		await Blake3TestUtils.VerifyCurrentHash(hasher, expected);
	}

	[Test]
	public async Task ConcurrentReadsMatchOneShot()
	{
		const int threads = 4;
		const int rounds = 64;
		const int pieceLength = 64;
		const int initialLength = 2 * 16384 + 15000;
		byte[] source = CreateDeterministicSource(initialLength + rounds);
		byte[][] actual = [.. Enumerable.Range(0, rounds).Select(_ => new byte[threads * pieceLength])];
		using Blake3HashAlgorithm hasher = Blake3HashAlgorithm.Create();
		int length = initialLength;

		// A reader that fails leaves the others waiting at the barrier, which the timeout then releases.
		using CancellationTokenSource timeout = new(TimeSpan.FromSeconds(30));
		using Barrier barrier = new
		(
			threads, _ =>
			{
				hasher.Reset();
				hasher.Append(source.AsSpan(0, length++));
			}
		);
		await Task.WhenAll(Enumerable.Range(0, threads).Select(thread => Task.Factory.StartNew(() => ReadPieces(thread * pieceLength), TaskCreationOptions.LongRunning)));

		for (int round = 0; round < rounds; ++round)
		{
			byte[] expected = Blake3TestUtils.HashData(Blake3Mode.Hash, source.AsSpan(0, initialLength + round), threads * pieceLength);
			await Assert.That(actual[round]).IsEquivalentTo(expected, CollectionOrdering.Matching);
		}

		void ReadPieces(int position)
		{
			for (int round = 0; round < rounds; ++round)
			{
				barrier.SignalAndWait(timeout.Token);
				hasher.GetCurrentHash(actual[round].AsSpan(position, pieceLength), (ulong)position);
			}
		}
	}

	[Test]
	public async Task DisposeErasesTheStateAndIsIdempotent()
	{
		byte[] source = CreateDeterministicSource(40000);
		byte[] destination = new byte[Blake3HashAlgorithm.HashLength];
		Blake3HashAlgorithm hasher = Blake3HashAlgorithm.CreateKeyed(Blake3TestVectors.Key);

		hasher.Append(source.AsSpan(0, 2000));
		hasher.Append(source.AsSpan(2000, 19000));
		hasher.GetCurrentHash(destination);
		hasher.Append(source.AsSpan(21000));
		hasher.GetCurrentHash(destination);

		// Dispose returns both arrays to the shared pool, which caches them for this thread; nothing rents from it before the check, so reading them stays valid.
		byte[] buffer = BufferArray(hasher) ?? [];
		byte[] stack = StackArray(hasher) ?? [];
		int bufferLength = State(hasher).BufferLength;
		int usedBufferLength = State(hasher).UsedBufferLength;
		int usedStackLength = State(hasher).UsedStackLength;
		bool heldState = StateBytes(hasher).ContainsAnyExcept((byte)0);
		bool heldOutput = OutputBytes(hasher).ContainsAnyExcept((byte)0);
		bool heldInput = usedBufferLength is Blake3State.GroupLength && buffer.AsSpan(0, bufferLength).SequenceEqual(source.AsSpan(source.Length - bufferLength));
		bool heldChainingValues = usedStackLength >= 3 * Blake3HashAlgorithm.HashLength && stack.AsSpan(0, usedStackLength).ContainsAnyExcept((byte)0);
		hasher.Dispose();
		bool erased = !StateBytes(hasher).ContainsAnyExcept((byte)0) && !OutputBytes(hasher).ContainsAnyExcept((byte)0);
		bool arraysErased = BufferArray(hasher) is null && StackArray(hasher) is null && !buffer.AsSpan(0, usedBufferLength).ContainsAnyExcept((byte)0) && !stack.AsSpan(0, usedStackLength).ContainsAnyExcept((byte)0);
		hasher.Dispose();

		using (Assert.Multiple())
		{
			await Assert.That(heldState).IsTrue();
			await Assert.That(heldOutput).IsTrue();
			await Assert.That(heldInput).IsTrue();
			await Assert.That(heldChainingValues).IsTrue();
			await Assert.That(erased).IsTrue();
			await Assert.That(arraysErased).IsTrue();
			await Assert.That(() => hasher.Append(destination)).ThrowsExactly<ObjectDisposedException>();
			await Assert.That(() => hasher.Append(destination, 2)).ThrowsExactly<ObjectDisposedException>();
			await Assert.That(() => hasher.GetCurrentHash(destination)).ThrowsExactly<ObjectDisposedException>();
			await Assert.That(() => hasher.GetCurrentHash(destination, 5)).ThrowsExactly<ObjectDisposedException>();
			await Assert.That(() => hasher.GetHashAndReset(destination)).ThrowsExactly<ObjectDisposedException>();
			await Assert.That(hasher.Reset).ThrowsExactly<ObjectDisposedException>();
			await Assert.That(hasher.Clone).ThrowsExactly<ObjectDisposedException>();
		}
	}

	[Test]
	[CombinedDataSources]
	public async Task ResetErasesAllButTheKeyInSecretModes([Arguments(Blake3Mode.KeyedHash, Blake3Mode.DeriveKey)] Blake3Mode mode, [Arguments(false, true)] bool getHashAndReset, [Arguments(false, true)] bool readLast)
	{
		const int length = 21300;
		byte[] source = CreateDeterministicSource(length);
		byte[] expected = Blake3TestUtils.ReferenceHash(mode, source, Blake3HashAlgorithm.HashLength);
		byte[] destination = new byte[Blake3HashAlgorithm.HashLength];
		using Blake3HashAlgorithm hasher = Blake3TestUtils.CreateHasher(mode);
		using Blake3HashAlgorithm fresh = Blake3TestUtils.CreateHasher(mode);

		for (int message = 0; message < 2; ++message)
		{
			hasher.Append(source.AsSpan(0, 2000));
			hasher.Append(source.AsSpan(2000, 19000));
			hasher.GetCurrentHash(destination);
			hasher.Append(source.AsSpan(21000, 100));
			hasher.GetCurrentHash(destination);
			hasher.Append(source.AsSpan(21100));

			if (readLast)
			{
				hasher.GetCurrentHash(destination);
			}

			byte[] buffer = BufferArray(hasher) ?? [];
			byte[] stack = StackArray(hasher) ?? [];
			int bufferLength = State(hasher).BufferLength;
			int usedBufferLength = State(hasher).UsedBufferLength;
			int usedStackLength = State(hasher).UsedStackLength;
			bool heldOutput = HasOutput(hasher) == readLast && OutputBytes(hasher).ContainsAnyExcept((byte)0);
			bool heldInput = usedBufferLength is Blake3State.GroupLength && buffer.AsSpan(0, bufferLength).SequenceEqual(source.AsSpan(length - bufferLength));
			bool heldChainingValues = usedStackLength >= 3 * Blake3HashAlgorithm.HashLength && stack.AsSpan(0, usedStackLength).ContainsAnyExcept((byte)0);
			bool heldChunkChainingValue = ChunkMode(hasher) && ChunkChainingValueBytes(hasher).ContainsAnyExcept((byte)0);
			byte[] hash = new byte[Blake3HashAlgorithm.HashLength + 1];
			PrepareDestination(hash);

			if (getHashAndReset)
			{
				hasher.GetHashAndReset(hash.AsSpan(0, Blake3HashAlgorithm.HashLength));
			}
			else
			{
				hasher.Reset();
			}

			bool erasedOutput = !OutputBytes(hasher).ContainsAnyExcept((byte)0);
			bool erasedArrays = !buffer.AsSpan(0, usedBufferLength).ContainsAnyExcept((byte)0) && !stack.AsSpan(0, usedStackLength).ContainsAnyExcept((byte)0);
			bool keptOnlyTheKey = StateBytes(hasher).SequenceEqual(StateBytes(fresh));

			using (Assert.Multiple())
			{
				await Assert.That(heldOutput).IsTrue();
				await Assert.That(heldInput).IsTrue();
				await Assert.That(heldChainingValues).IsTrue();
				await Assert.That(heldChunkChainingValue).IsTrue();
				await Assert.That(erasedOutput).IsTrue();
				await Assert.That(erasedArrays).IsTrue();
				await Assert.That(keptOnlyTheKey).IsTrue();
			}

			if (getHashAndReset)
			{
				await AssertOutput(hash, expected);
			}
		}

		hasher.Append(source.AsSpan(0, 3000));
		await Blake3TestUtils.VerifyCurrentHash(hasher, Blake3TestUtils.ReferenceHash(mode, source.AsSpan(0, 3000), OutputLength));
	}

	[Test]
	[Arguments(63, 1)]
	[Arguments(999, 1)]
	[Arguments(1024, 1)]
	[Arguments(1025, 1)]
	[Arguments(2048, 1)]
	[Arguments(5000, 1)]
	[Arguments(16384, 1)]
	[Arguments(20000, 1)]
	[Arguments(64, 3)]
	[Arguments(300, 3)]
	[Arguments(64, 40)]
	[Arguments(100, 50)]
	[Arguments(999, 5)]
	[Arguments(1024, 17)]
	[Arguments(3000, 2)]
	[Arguments(4096, 4)]
	[Arguments(8192, 2)]
	[Arguments(16383, 2)]
	public async Task ReadsBetweenAppendsMatchReference(int pieceLength, int readEvery)
	{
		byte[] source = CreateDeterministicSource(3 * 16384 + 5000);
		(int, bool)[] pieces = [.. Enumerable.Range(0, (source.Length + pieceLength - 1) / pieceLength).Select(i => (pieceLength, (i + 1) % readEvery is 0))];

		foreach (Blake3Mode mode in Blake3TestUtils.Modes)
		{
			await Assert.That(FirstMismatchingRead(mode, source, pieces)).IsEqualTo(-1);
		}
	}

	[Test]
	[Arguments(1U)]
	[Arguments(2U)]
	[Arguments(3U)]
	public async Task ReadsAtRandomBetweenAppendsMatchReference(uint seed)
	{
		byte[] source = CreateDeterministicSource(200_000);
		List<(int, bool)> pieces = [];
		uint state = seed;

		for (int length = 0; length < source.Length;)
		{
			state = state * 1664525U + 1013904223U;
			int maximumLength = (state >> 28) switch { < 6 => 100, < 12 => 5000, _ => 40000 };
			int pieceLength = (int)(state % (uint)maximumLength) + 1;
			pieces.Add((pieceLength, (state & 0x100) is 0));
			length += pieceLength;
		}

		foreach (Blake3Mode mode in Blake3TestUtils.Modes)
		{
			await Assert.That(FirstMismatchingRead(mode, source, pieces)).IsEqualTo(-1);
		}
	}

	[Test]
	[MethodDataSource(typeof(Blake3TestUtils), nameof(Blake3TestUtils.Modes))]
	public async Task StateAfterReadsSupportsTheLifecycle(Blake3Mode mode)
	{
		const int headLength = 4 * 1024 + 500;
		const int pieceLength = 1000;
		const int pieces = 40;
		int length = headLength + 2 + pieces * pieceLength;
		byte[] source = CreateDeterministicSource(length + 300_000);
		byte[] destination = new byte[Blake3HashAlgorithm.HashLength];
		using Blake3HashAlgorithm hasher = Blake3TestUtils.CreateHasher(mode);

		hasher.Append(source.AsSpan(0, headLength));
		hasher.GetCurrentHash(destination);
		hasher.Append(source.AsSpan(headLength, 1));
		hasher.GetCurrentHash(destination);
		hasher.Append(source.AsSpan(headLength + 1, 1));
		bool tookChunkMode = ChunkMode(hasher) && State(hasher).BufferLength is 502;
		await Blake3TestUtils.VerifyCurrentHash(hasher, Blake3TestUtils.ReferenceHash(mode, source.AsSpan(0, headLength + 2), OutputLength));

		using Blake3HashAlgorithm clone = hasher.Clone();
		clone.Append(source.AsSpan(headLength + 2), -1);
		await Blake3TestUtils.VerifyCurrentHash(clone, Blake3TestUtils.ReferenceHash(mode, source, OutputLength));

		HashAlgorithmTestUtils.AppendInPieces(hasher, source.AsSpan(headLength + 2, pieces * pieceLength), pieceLength);
		bool leftChunkMode = !ChunkMode(hasher) && State(hasher).BufferLength > 1024;
		await Blake3TestUtils.VerifyCurrentHash(hasher, Blake3TestUtils.ReferenceHash(mode, source.AsSpan(0, length), OutputLength));
		hasher.Append(source.AsSpan(length), 4);
		await Blake3TestUtils.VerifyCurrentHash(hasher, Blake3TestUtils.ReferenceHash(mode, source, OutputLength));

		using (Assert.Multiple())
		{
			await Assert.That(tookChunkMode).IsTrue();
			await Assert.That(leftChunkMode).IsTrue();
		}

		hasher.Reset();
		await Blake3TestUtils.VerifyCurrentHash(hasher, Blake3TestUtils.ReferenceHash(mode, [], OutputLength));
		HashAlgorithmTestUtils.AppendInPieces(hasher, source.AsSpan(0, length), 5000);
		await Blake3TestUtils.VerifyCurrentHash(hasher, Blake3TestUtils.ReferenceHash(mode, source.AsSpan(0, length), OutputLength));
	}

	[Test]
	public async Task RejectsInvalidArguments()
	{
		byte[] destination = new byte[Blake3HashAlgorithm.HashLength];
		PrepareDestination(destination);
		byte[] key = new byte[Blake3HashAlgorithm.KeyLengthInBytes];
		using Blake3HashAlgorithm hasher = Blake3HashAlgorithm.Create();

		using (Assert.Multiple())
		{
			foreach (int keyLength in new[] { 0, 31, 33 })
			{
				byte[] invalidKey = new byte[keyLength];
				await Assert.That(() => Blake3HashAlgorithm.CreateKeyed(invalidKey)).ThrowsExactly<ArgumentOutOfRangeException>().WithParameterName("key");
				await Assert.That(() => Blake3HashAlgorithm.KeyedHashData(invalidKey, [], destination)).ThrowsExactly<ArgumentOutOfRangeException>().WithParameterName("key");
			}

			foreach (int maxDegreeOfParallelism in new[] { 0, -2, int.MinValue })
			{
				await Assert.That(() => Blake3HashAlgorithm.HashData([], destination, maxDegreeOfParallelism)).ThrowsExactly<ArgumentOutOfRangeException>().WithParameterName("maxDegreeOfParallelism");
				await Assert.That(() => Blake3HashAlgorithm.KeyedHashData(key, [], destination, maxDegreeOfParallelism)).ThrowsExactly<ArgumentOutOfRangeException>().WithParameterName("maxDegreeOfParallelism");
				await Assert.That(() => Blake3HashAlgorithm.DeriveKey([], [], destination, maxDegreeOfParallelism)).ThrowsExactly<ArgumentOutOfRangeException>().WithParameterName("maxDegreeOfParallelism");
				await Assert.That(() => hasher.Append([], maxDegreeOfParallelism)).ThrowsExactly<ArgumentOutOfRangeException>().WithParameterName("maxDegreeOfParallelism");
				await Assert.That(() => hasher.GetCurrentHash(destination, 0, maxDegreeOfParallelism)).ThrowsExactly<ArgumentOutOfRangeException>().WithParameterName("maxDegreeOfParallelism");
			}

			await Assert.That(destination).All(static value => value is DestinationSentinel);
		}
	}

	[Test]
	[Arguments(0)]
	[Arguments(1)]
	[Arguments(1024)]
	[Arguments(1025)]
	[Arguments(5000)]
	public async Task DeriveKeyAcceptsContextsOfAnyLength(int contextLength)
	{
		byte[] context = CreateDeterministicSource(contextLength);
		byte[] keyMaterial = CreateDeterministicSource(2000);
		Blake3Reference reference = Blake3Reference.CreateDeriveKey(context);
		reference.Update(keyMaterial);
		byte[] expected = new byte[OutputLength];
		reference.Finalize(expected);

		byte[] oneShot = new byte[OutputLength];
		Blake3HashAlgorithm.DeriveKey(context, keyMaterial, oneShot);
		using Blake3HashAlgorithm hasher = Blake3HashAlgorithm.CreateDeriveKey(context);
		hasher.Append(keyMaterial);

		await Assert.That(oneShot).IsEquivalentTo(expected, CollectionOrdering.Matching);
		await Blake3TestUtils.VerifyCurrentHash(hasher, expected);
	}

	[Test]
	[CombinedDataSources]
	public async Task HashDataSupportsOverlappingSourceAndDestination([Arguments(1, 1025, 132097)] int length, [Arguments(1, -1)] int maxDegreeOfParallelism)
	{
		byte[] source = CreateDeterministicSource(length);

		foreach (Blake3Mode mode in Blake3TestUtils.Modes)
		{
			byte[] expected = Blake3TestUtils.HashData(mode, source, OutputLength);
			await HashAlgorithmTestUtils.VerifyOverlappingHashData
			(
				source, expected, (input, output) =>
				{
					Blake3TestUtils.HashData(mode, input, output.Slice(0, OutputLength), maxDegreeOfParallelism);
					return OutputLength;
				}
			);
		}
	}

	private static int FirstMismatchingRead(Blake3Mode mode, byte[] source, IEnumerable<(int Length, bool Read)> pieces)
	{
		using Blake3HashAlgorithm hasher = Blake3TestUtils.CreateHasher(mode);
		Blake3Reference reference = Blake3TestUtils.CreateReference(mode);
		byte[] actual = new byte[OutputLength];
		byte[] expected = new byte[OutputLength];
		int offset = 0;

		foreach ((int length, bool read) in pieces)
		{
			ReadOnlySpan<byte> piece = source.AsSpan(offset, Math.Min(length, source.Length - offset));
			hasher.Append(piece);
			reference.Update(piece);
			offset += piece.Length;

			if (read || offset == source.Length)
			{
				hasher.GetCurrentHash(actual);
				reference.Finalize(expected);

				if (!actual.AsSpan().SequenceEqual(expected))
				{
					return offset;
				}
			}
		}

		return -1;
	}

	private static ReadOnlySpan<byte> StateBytes(Blake3HashAlgorithm hasher)
	{
		return MemoryMarshal.AsBytes(new ReadOnlySpan<Blake3State>(ref State(hasher)));
	}

	private static ReadOnlySpan<byte> OutputBytes(Blake3HashAlgorithm hasher)
	{
		return MemoryMarshal.AsBytes(new ReadOnlySpan<Blake3Output>(ref Output(hasher)));
	}

	private static ReadOnlySpan<byte> ChunkChainingValueBytes(Blake3HashAlgorithm hasher)
	{
		return MemoryMarshal.AsBytes(new ReadOnlySpan<InlineArray8<uint>>(ref ChunkChainingValue(ref State(hasher))));
	}

	[UnsafeAccessor(UnsafeAccessorKind.Field, Name = "_state")]
	private static extern ref Blake3State State(Blake3HashAlgorithm hasher);

	[UnsafeAccessor(UnsafeAccessorKind.Field, Name = "_chunkChainingValue")]
	private static extern ref InlineArray8<uint> ChunkChainingValue(ref Blake3State state);

	[UnsafeAccessor(UnsafeAccessorKind.Field, Name = "_output")]
	private static extern ref Blake3Output Output(Blake3HashAlgorithm hasher);

	[UnsafeAccessor(UnsafeAccessorKind.Field, Name = "_hasOutput")]
	private static extern ref bool HasOutput(Blake3HashAlgorithm hasher);

	[UnsafeAccessor(UnsafeAccessorKind.Field, Name = "_chunkMode")]
	private static extern ref bool ChunkMode(Blake3HashAlgorithm hasher);

	[UnsafeAccessor(UnsafeAccessorKind.Field, Name = "_buffer")]
	private static extern ref byte[]? BufferArray(Blake3HashAlgorithm hasher);

	[UnsafeAccessor(UnsafeAccessorKind.Field, Name = "_stack")]
	private static extern ref byte[]? StackArray(Blake3HashAlgorithm hasher);
}
