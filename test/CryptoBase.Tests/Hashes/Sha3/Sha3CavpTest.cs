using CryptoBase.Abstractions.Hashes;
using CryptoBase.Hashes;
using CryptoBase.Hashes.Sha3;
using CryptoBase.Tests.Cavp;
using static CryptoBase.Tests.Hashes.HashAlgorithmTestUtils;
using static CryptoBase.Tests.TestUtils;

namespace CryptoBase.Tests.Hashes.Sha3;

// NIST CAVP byte-oriented SHA-3 vectors; see Cavp/Sha3/README.md for their source and sampling.
public class Sha3CavpTest
{
	private const int MonteCarloCheckpoints = 100;
	private const int MonteCarloIterations = 1000;

	[Test]
	[CavpRecords("SHA3_224ShortMsg.rsp")]
	[CavpRecords("SHA3_224LongMsg.rsp")]
	public Task Sha3_224Messages(CavpRecord record)
	{
		return VerifyMessage<Sha3_224Core>(record);
	}

	[Test]
	[CavpRecords("SHA3_256ShortMsg.rsp")]
	[CavpRecords("SHA3_256LongMsg.rsp")]
	public Task Sha3_256Messages(CavpRecord record)
	{
		return VerifyMessage<Sha3_256Core>(record);
	}

	[Test]
	[CavpRecords("SHA3_384ShortMsg.rsp")]
	[CavpRecords("SHA3_384LongMsg.rsp")]
	public Task Sha3_384Messages(CavpRecord record)
	{
		return VerifyMessage<Sha3_384Core>(record);
	}

	[Test]
	[CavpRecords("SHA3_512ShortMsg.rsp")]
	[CavpRecords("SHA3_512LongMsg.rsp")]
	public Task Sha3_512Messages(CavpRecord record)
	{
		return VerifyMessage<Sha3_512Core>(record);
	}

	[Test]
	public Task Sha3_224MonteCarlo()
	{
		return VerifyMonteCarlo<Sha3_224Core>("SHA3_224Monte.rsp");
	}

	[Test]
	public Task Sha3_256MonteCarlo()
	{
		return VerifyMonteCarlo<Sha3_256Core>("SHA3_256Monte.rsp");
	}

	[Test]
	public Task Sha3_384MonteCarlo()
	{
		return VerifyMonteCarlo<Sha3_384Core>("SHA3_384Monte.rsp");
	}

	[Test]
	public Task Sha3_512MonteCarlo()
	{
		return VerifyMonteCarlo<Sha3_512Core>("SHA3_512Monte.rsp");
	}

	// Guards the embedding and sampling: ShortMsg covers every length from 0 to the rate, and Monte holds the seed and its checkpoints.
	[Test]
	[Arguments("SHA3_224ShortMsg.rsp", 145)]
	[Arguments("SHA3_256ShortMsg.rsp", 137)]
	[Arguments("SHA3_384ShortMsg.rsp", 105)]
	[Arguments("SHA3_512ShortMsg.rsp", 73)]
	[Arguments("SHA3_224LongMsg.rsp", 14)]
	[Arguments("SHA3_256LongMsg.rsp", 14)]
	[Arguments("SHA3_384LongMsg.rsp", 14)]
	[Arguments("SHA3_512LongMsg.rsp", 14)]
	[Arguments("SHA3_224Monte.rsp", MonteCarloCheckpoints + 1)]
	[Arguments("SHA3_256Monte.rsp", MonteCarloCheckpoints + 1)]
	[Arguments("SHA3_384Monte.rsp", MonteCarloCheckpoints + 1)]
	[Arguments("SHA3_512Monte.rsp", MonteCarloCheckpoints + 1)]
	public async Task FilesHaveAllRecords(string fileName, int expectedCount)
	{
		await Assert.That(CavpRspFile.Load(fileName).Records).Count().IsEqualTo(expectedCount);
	}

	// The reference stands in for the platform where it lacks SHA-3, so it must itself pass the vectors.
	[Test]
	[Arguments("SHA3_224ShortMsg.rsp")]
	[Arguments("SHA3_256ShortMsg.rsp")]
	[Arguments("SHA3_384ShortMsg.rsp")]
	[Arguments("SHA3_512ShortMsg.rsp")]
	[Arguments("SHA3_224LongMsg.rsp")]
	[Arguments("SHA3_256LongMsg.rsp")]
	[Arguments("SHA3_384LongMsg.rsp")]
	[Arguments("SHA3_512LongMsg.rsp")]
	public async Task ReferenceMatchesVectors(string fileName)
	{
		foreach (CavpRecord record in CavpRspFile.Load(fileName).Records)
		{
			byte[] expected = record.GetBytes("MD");
			await Assert.That(KeccakReference.Sha3(record.GetMessage(), expected.Length)).IsEquivalentTo(expected, CollectionOrdering.Matching);
		}
	}

	private static async Task VerifyMessage<T>(CavpRecord record) where T : unmanaged, IHmacHashCore<T>
	{
		byte[] message = record.GetMessage();
		byte[] expected = record.GetBytes("MD");

		await Assert.That(record.GetHeaderInt32("L")).IsEqualTo(T.HashLength * 8);
		await VerifyBoundary<T>(message, expected);

		// VerifyBoundary appends pieces shorter than a block; these also span blocks from arbitrary offsets.
		using HashAlgorithm<T> hashAlgorithm = HashAlgorithm<T>.Create();
		AppendInPseudoRandomPieces(hashAlgorithm, message, (uint)message.Length, 3 * T.HmacBlockSize);
		byte[] destination = CreateDestination<T>();
		PrepareDestination(destination);
		int written = hashAlgorithm.GetHashAndReset(destination);
		await AssertOutput(destination, expected, written);
	}

	// SHA3VS, Sec. 6.2.3: each checkpoint is the digest after 1000 iterations of hashing the previous digest, starting from the seed.
	private static async Task VerifyMonteCarlo<T>(string fileName) where T : unmanaged, IHashCore<T>
	{
		IReadOnlyList<CavpRecord> records = CavpRspFile.Load(fileName).Records;
		byte[] digest = records[0].GetBytes("Seed");
		byte[] next = new byte[T.HashLength];

		await Assert.That(records).Count().IsEqualTo(MonteCarloCheckpoints + 1);
		await Assert.That(records[0].GetHeaderInt32("L")).IsEqualTo(T.HashLength * 8);
		await Assert.That(digest.Length).IsEqualTo(T.HashLength);

		for (int checkpoint = 0; checkpoint < MonteCarloCheckpoints; ++checkpoint)
		{
			for (int i = 0; i < MonteCarloIterations; ++i)
			{
				HashAlgorithm<T>.HashData(digest, next);
				(digest, next) = (next, digest);
			}

			CavpRecord record = records[checkpoint + 1];
			await Assert.That(record.GetInt32("COUNT")).IsEqualTo(checkpoint);
			await Assert.That(digest).IsEquivalentTo(record.GetBytes("MD"), CollectionOrdering.Matching);
		}
	}
}
