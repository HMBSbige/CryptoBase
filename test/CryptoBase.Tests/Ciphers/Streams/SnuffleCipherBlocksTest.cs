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
		[Arguments(0, 63, 64, 65, 255, 256, 257, 511, 512, 513, 1023, 1024, 1025, 2047, 2048, 2049)]
		int length
	)
	{
		using SnuffleCipher byteWise = cipher.Create();
		using SnuffleCipher bulk = cipher.Create();
		await TestBlocks(byteWise, bulk, length);
	}
}
