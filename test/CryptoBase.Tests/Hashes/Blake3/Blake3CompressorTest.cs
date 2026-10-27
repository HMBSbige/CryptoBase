using CryptoBase.Hashes.Blake3;
using static CryptoBase.Tests.Hashes.Blake3.Blake3Reference;
using static CryptoBase.Tests.TestUtils;

namespace CryptoBase.Tests.Hashes.Blake3;

public class Blake3CompressorTest
{
	private const int MaxBlockCount = 17;

	private static readonly ulong[] Counters = [0, 7, uint.MaxValue, 1UL << 32, 0xFEDC_BA98_7654_3210];

	private static readonly uint[] ModeFlags = [0, KeyedHash, DeriveKeyContext, DeriveKeyMaterial];

	private static readonly (uint StartFlags, uint EndFlags)[] ChunkFlags = [(ChunkStart, ChunkEnd), (ChunkStart, 0), (0, ChunkEnd), (0, 0)];

	private static readonly uint[] BlockLengths = [0, 1, 32, 63, 64];

	private static readonly uint[] NodeFlags = [Parent, Parent | Root, ChunkStart | ChunkEnd, ChunkEnd | Root | KeyedHash, ChunkStart | DeriveKeyMaterial];

	[Test]
	public async Task EveryCompressorIsListed()
	{
		await Assert.That(Blake3CompressorCase.All().Select(static compressor => compressor.CompressorType)).IsEquivalentTo(ImplementationsOf(typeof(IBlake3Compressor)));
	}

	[Test]
	[MethodDataSource(typeof(Blake3CompressorCase), nameof(Blake3CompressorCase.All))]
	public async Task CompressBlocksMatchesReference(Blake3CompressorCase compressor)
	{
		SkipUnlessSupported(compressor);

		ReadOnlyMemory<byte> blocks = CreateDeterministicSource(MaxBlockCount * BlockLength + 1).AsMemory(1);
		uint[] initial = WordsFromLittleEndianBytes(CreateDeterministicSource(OutLength));

		foreach (uint flags in ModeFlags)
		{
			foreach ((uint startFlags, uint endFlags) in ChunkFlags)
			{
				foreach (ulong counter in Counters)
				{
					for (int blockCount = 1; blockCount <= MaxBlockCount; ++blockCount)
					{
						uint[] expected = initial;

						for (int i = 0; i < blockCount; ++i)
						{
							uint blockFlags = flags | (i is 0 ? startFlags : 0) | (i == blockCount - 1 ? endFlags : 0);
							expected = WordsFromLittleEndianBytes(CompressBytes(expected, blocks.Span.Slice(i * BlockLength, BlockLength), counter, BlockLength, blockFlags).AsSpan(0, OutLength));
						}

						uint[] actual = (uint[])initial.Clone();
						compressor.CompressBlocks(actual, blocks.Span, blockCount, counter, flags, startFlags, endFlags);
						await Assert.That(actual).IsEquivalentTo(expected, CollectionOrdering.Matching);
					}
				}
			}
		}
	}

	[Test]
	[MethodDataSource(typeof(Blake3CompressorCase), nameof(Blake3CompressorCase.All))]
	public async Task CompressMatchesReference(Blake3CompressorCase compressor)
	{
		SkipUnlessSupported(compressor);

		uint[] chainingValue = WordsFromLittleEndianBytes(CreateDeterministicSource(OutLength));
		byte[] block = CreateDeterministicSource(BlockLength);

		foreach (uint blockLength in BlockLengths)
		{
			foreach (uint flags in NodeFlags)
			{
				foreach (ulong counter in Counters)
				{
					byte[] expected = CompressBytes(chainingValue, block, counter, blockLength, flags);
					byte[] expectedChainingValue = expected.AsSpan(0, OutLength).ToArray();

					byte[] output = new byte[BlockLength + 1];
					PrepareDestination(output);
					compressor.Compress(chainingValue, block, blockLength, counter, flags, output);
					await AssertOutput(output, expectedChainingValue);

					PrepareDestination(output);
					compressor.CompressXof(chainingValue, block, blockLength, counter, flags, output);
					await AssertOutput(output, expected);

					foreach (int offset in new[] { 0, OutLength })
					{
						byte[] inPlace = (byte[])block.Clone();
						byte[] expectedInPlace = (byte[])block.Clone();
						expectedChainingValue.CopyTo(expectedInPlace, offset);
						compressor.Compress(chainingValue, inPlace, blockLength, counter, flags, inPlace.AsSpan(offset));
						await Assert.That(inPlace).IsEquivalentTo(expectedInPlace, CollectionOrdering.Matching);
					}

					byte[] xofInPlace = (byte[])block.Clone();
					compressor.CompressXof(chainingValue, xofInPlace, blockLength, counter, flags, xofInPlace);
					await Assert.That(xofInPlace).IsEquivalentTo(expected, CollectionOrdering.Matching);
				}
			}
		}
	}
}
