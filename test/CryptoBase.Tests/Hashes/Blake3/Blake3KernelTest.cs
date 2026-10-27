using CryptoBase.Hashes.Blake3;
using static CryptoBase.Tests.Hashes.Blake3.Blake3Reference;
using static CryptoBase.Tests.TestUtils;

namespace CryptoBase.Tests.Hashes.Blake3;

public class Blake3KernelTest
{
	private static readonly ulong[] Counters = [0, 5, uint.MaxValue - 6, uint.MaxValue, 1UL << 32, 0x0123_4567_FFFF_FFF9];

	private static readonly uint[] ModeFlags = [0, KeyedHash, DeriveKeyMaterial];

	private static readonly int[] PartialChunkLengths = [.. Enumerable.Range(1, ChunkLength / BlockLength).SelectMany(static blocks => (int[])[(blocks - 1) * BlockLength + 1, Math.Min(blocks * BlockLength, ChunkLength - 1)])];

	[Test]
	public async Task EveryKernelIsListed()
	{
		await Assert.That(Blake3KernelCase.All().Select(static kernel => kernel.KernelType)).IsEquivalentTo(ImplementationsOf(typeof(IBlake3Kernel)));
	}

	[Test]
	[MethodDataSource(typeof(Blake3KernelCase), nameof(Blake3KernelCase.All))]
	public async Task HashChunksMatchesReference(Blake3KernelCase kernel)
	{
		SkipUnlessSupported(kernel);

		int maxCount = MaxCount(kernel);
		ReadOnlyMemory<byte> input = CreateMisalignedSource(maxCount * ChunkLength);

		foreach (uint flags in ModeFlags)
		{
			uint[] key = CreateKey(flags);

			foreach (ulong counter in Counters)
			{
				byte[] expected = new byte[maxCount * OutLength];

				for (int i = 0; i < maxCount; ++i)
				{
					ChunkChainingValue(input.Span.Slice(i * ChunkLength, ChunkLength), key, counter + (ulong)i, flags).CopyTo(expected, i * OutLength);
				}

				for (int count = 1; count <= maxCount; ++count)
				{
					byte[] output = new byte[(count + 1) * OutLength];
					PrepareDestination(output);
					kernel.HashChunks(input.Span.Slice(0, count * ChunkLength), key, counter, flags, output);
					await AssertOutput(output, expected.AsSpan(0, count * OutLength).ToArray());
				}
			}
		}
	}

	[Test]
	[MethodDataSource(typeof(Blake3KernelCase), nameof(Blake3KernelCase.All))]
	public async Task HashChunksWithPartialLastChunkMatchesReference(Blake3KernelCase kernel)
	{
		SkipUnlessSupported(kernel);

		int maxCount = MaxCount(kernel);
		ReadOnlyMemory<byte> input = CreateMisalignedSource(maxCount * ChunkLength);

		foreach (uint flags in ModeFlags)
		{
			uint[] key = CreateKey(flags);

			foreach (ulong counter in (ulong[])[0, 0x0123_4567_FFFF_FFF9])
			{
				byte[] expected = new byte[maxCount * OutLength];

				for (int count = 0; count < maxCount; ++count)
				{
					foreach (int partialLength in PartialChunkLengths)
					{
						ChunkChainingValue(input.Span.Slice(count * ChunkLength, partialLength), key, counter + (ulong)count, flags).CopyTo(expected, count * OutLength);
						byte[] output = new byte[(count + 2) * OutLength];
						PrepareDestination(output);
						kernel.HashChunks(input.Span.Slice(0, count * ChunkLength + partialLength), key, counter, flags, output);
						await AssertOutput(output, expected.AsSpan(0, (count + 1) * OutLength).ToArray());
					}

					ChunkChainingValue(input.Span.Slice(count * ChunkLength, ChunkLength), key, counter + (ulong)count, flags).CopyTo(expected, count * OutLength);
				}
			}
		}
	}

	[Test]
	[MethodDataSource(typeof(Blake3KernelCase), nameof(Blake3KernelCase.All))]
	public async Task HashParentsMatchesReference(Blake3KernelCase kernel)
	{
		SkipUnlessSupported(kernel);

		int maxCount = MaxCount(kernel);
		ReadOnlyMemory<byte> input = CreateMisalignedSource(maxCount * BlockLength);

		foreach (uint flags in ModeFlags)
		{
			uint[] key = CreateKey(flags);
			byte[] expected = new byte[maxCount * OutLength];

			for (int i = 0; i < maxCount; ++i)
			{
				ParentChainingValue(input.Span.Slice(i * BlockLength, BlockLength), key, flags).CopyTo(expected, i * OutLength);
			}

			for (int count = 1; count <= maxCount; ++count)
			{
				byte[] expectedRow = expected.AsSpan(0, count * OutLength).ToArray();
				byte[] output = new byte[(count + 1) * OutLength];
				PrepareDestination(output);
				kernel.HashParents(input.Span, count, key, flags, output);
				await AssertOutput(output, expectedRow);

				byte[] row = new byte[(count + 1) * BlockLength];
				PrepareDestination(row);
				input.Span.Slice(0, count * BlockLength).CopyTo(row);
				kernel.HashParents(row, count, key, flags, row);

				using (Assert.Multiple())
				{
					await Assert.That(row.AsMemory(0, expectedRow.Length)).IsEquivalentTo(expectedRow, CollectionOrdering.Matching);
					await Assert.That(row.AsMemory(count * BlockLength)).All(static value => value is DestinationSentinel);
				}
			}
		}
	}

	[Test]
	[MethodDataSource(typeof(Blake3KernelCase), nameof(Blake3KernelCase.WithXof))]
	public async Task XofManyMatchesReference(Blake3KernelCase kernel)
	{
		SkipUnlessSupported(kernel);

		int maxCount = MaxCount(kernel);
		uint[] chainingValue = WordsFromLittleEndianBytes(CreateDeterministicSource(OutLength));
		byte[] block = CreateDeterministicSource(BlockLength);
		(uint BlockLength, uint Flags)[] nodes =
		[
			(BlockLength, Parent | Root),
			(0, ChunkStart | ChunkEnd | Root),
			(1, ChunkEnd | Root | KeyedHash),
			(63, ChunkStart | ChunkEnd | Root | DeriveKeyMaterial)
		];

		foreach ((uint blockLength, uint flags) in nodes)
		{
			foreach (ulong counter in Counters)
			{
				byte[] expected = new byte[maxCount * BlockLength];

				for (int i = 0; i < maxCount; ++i)
				{
					CompressBytes(chainingValue, block, counter + (ulong)i, blockLength, flags).CopyTo(expected, i * BlockLength);
				}

				for (int count = 1; count <= maxCount; ++count)
				{
					byte[] output = new byte[(count + 1) * BlockLength];
					PrepareDestination(output);
					kernel.XofMany(chainingValue, block, blockLength, counter, flags, count, output);
					await AssertOutput(output, expected.AsSpan(0, count * BlockLength).ToArray());
				}
			}
		}
	}

	[Test]
	[MethodDataSource(typeof(Blake3KernelCase), nameof(Blake3KernelCase.All))]
	public async Task CompressSubtreeToParentNodeMatchesReference(Blake3KernelCase kernel)
	{
		SkipUnlessSupported(kernel);

		int row = kernel.Degree * ChunkLength;
		int[] lengths =
		[
			ChunkLength + 1, 2 * ChunkLength, 2 * ChunkLength + 1, 3 * ChunkLength + 5,
			row, row + 1, 2 * row - 1, 2 * row, 2 * row + 1, 5 * row + 7,
			31 * ChunkLength + 1, 64 * ChunkLength + 1
		];

		ulong[] chunkCounters = [0, (1UL << 32) - 64, 1UL << 40];

		foreach (int length in lengths.Where(static length => length > ChunkLength).Distinct())
		{
			ReadOnlyMemory<byte> input = CreateMisalignedSource(length);

			foreach (uint flags in ModeFlags)
			{
				uint[] key = CreateKey(flags);

				foreach (ulong chunkCounter in chunkCounters)
				{
					byte[] output = new byte[2 * OutLength + 1];
					PrepareDestination(output);
					kernel.CompressSubtreeToParentNode(input.Span, key, chunkCounter, flags, output.AsSpan(0, 2 * OutLength));
					await AssertOutput(output, SubtreeChildren(input.Span, key, chunkCounter, flags));
				}
			}
		}
	}

	private static int MaxCount(Blake3KernelCase kernel)
	{
		return 2 * kernel.Degree + 1;
	}

	private static ReadOnlyMemory<byte> CreateMisalignedSource(int length)
	{
		return CreateDeterministicSource(length + 1).AsMemory(1);
	}

	private static uint[] CreateKey(uint flags)
	{
		return flags is 0 ? IV : WordsFromLittleEndianBytes(CreateDeterministicSource(KeyLength + (int)flags).AsSpan(0, KeyLength));
	}
}
