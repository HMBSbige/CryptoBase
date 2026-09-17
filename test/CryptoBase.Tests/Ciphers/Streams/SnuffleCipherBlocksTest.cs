using CryptoBase.Ciphers.Streams;
using static CryptoBase.Tests.Ciphers.Streams.SnuffleCipherTestUtils;
using static CryptoBase.Tests.TestUtils;

namespace CryptoBase.Tests.Ciphers.Streams;

public class SnuffleCipherBlocksTest
{
	[Test]
	[CombinedDataSources]
	public async Task CriticalBlockBoundariesMatchByteWiseProcessing
	(
		[MethodDataSource(typeof(SnuffleCipherTestUtils), nameof(CipherCases))]
		SnuffleCase cipher,
		[Arguments(0, 63, 64, 65, 127, 128, 129, 191, 192, 193, 255, 256, 257, 319, 320, 321, 383, 384, 385, 447, 448, 449, 511, 512, 513, 575, 576, 577, 639, 640, 641, 703, 704, 705, 767, 768, 769, 1023, 1024, 1025, 1087, 1088, 1089, 1535, 1536, 1537, 2047, 2048, 2049)]
		int length
	)
	{
		using SnuffleCipher byteWise = cipher.Create();
		using SnuffleCipher bulk = cipher.Create();
		await TestBlocks(byteWise, bulk, length);
	}

	[Test]
	[CombinedDataSources]
	public async Task UnalignedBulkAndSegmentedInPlacePreserveSurroundingBytes
	(
		[MethodDataSource(typeof(SnuffleCipherTestUtils), nameof(CipherCases))]
		SnuffleCase cipher,
		[Arguments(127, 128, 129, 191, 192, 193, 255, 256, 257, 319, 320, 321, 383, 384, 385, 447, 448, 449, 511, 512, 513, 575, 576, 577, 639, 640, 641, 703, 704, 705, 767, 768, 769, 831, 832, 833, 895, 896, 897, 959, 960, 961, 1023, 1024, 1025, 1087, 1088, 1089, 1279, 1280, 1281, 1535, 1536, 1537, 1983, 1984, 1985, 2047, 2048, 2049, 8192)]
		int length
	)
	{
		byte[] source = CreateDeterministicSource(length + 3);
		byte[] expected = new byte[length];
		ulong counter = cipher.MaxCounter is uint.MaxValue ? 7UL : 0x12345678FFFFFFF9;
		using SnuffleCipher byteWise = cipher.Create();
		SetCounter(byteWise, counter);

		for (int i = 0; i < length; ++i)
		{
			byteWise.Xor(source.AsSpan(i + 3, 1), expected.AsSpan(i, 1));
		}

		for (int mode = 0; mode < 3; ++mode)
		{
			using SnuffleCipher subject = cipher.Create();
			SetCounter(subject, counter);
			byte[] output = new byte[length + 80];
			PrepareDestination(output);

			if (mode is 0)
			{
				subject.Xor(source.AsSpan(3, length), output.AsSpan(7));
			}
			else
			{
				source.AsSpan(3, length).CopyTo(output.AsSpan(7));
				int offset = 0;

				while (offset < length)
				{
					int take = mode is 1 ? length : Math.Min(length - offset, offset is 0 ? 127 : 575);
					subject.Xor(output.AsSpan(offset + 7, take), output.AsSpan(offset + 7));
					offset += take;
				}
			}

			await Assert.That(output.AsMemory(7, length)).IsEquivalentTo(expected, CollectionOrdering.Matching);
			await Assert.That(output.AsMemory(0, 7)).All(static value => value is DestinationSentinel);
			await Assert.That(output.AsMemory(length + 7)).All(static value => value is DestinationSentinel);
		}
	}
}
