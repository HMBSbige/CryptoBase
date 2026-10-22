using CryptoBase.Abstractions.Hashes;
using CryptoBase.Hashes;
using CryptoBase.Hashes.Sha3;
using CryptoBase.Tests.Cavp;
using System.Buffers.Binary;
using static CryptoBase.Tests.TestUtils;

namespace CryptoBase.Tests.Hashes.Sha3;

// NIST CAVP byte-oriented SHAKE vectors; see Cavp/Shake/README.md for their source and sampling.
public class ShakeCavpTest
{
	private const int MonteCarloCheckpoints = 100;
	private const int MonteCarloIterations = 1000;
	private const int MonteCarloMessageLength = 16;

	public static IEnumerable<CavpRecord> Records(string fileName)
	{
		return CavpRspFile.Load(fileName).Records;
	}

	[Test]
	[MethodDataSource(nameof(Records), Arguments = ["SHAKE128ShortMsg.rsp"])]
	[MethodDataSource(nameof(Records), Arguments = ["SHAKE128LongMsg.rsp"])]
	public Task Shake128Messages(CavpRecord record)
	{
		return VerifyMessage<Shake128Core>(record);
	}

	[Test]
	[MethodDataSource(nameof(Records), Arguments = ["SHAKE256ShortMsg.rsp"])]
	[MethodDataSource(nameof(Records), Arguments = ["SHAKE256LongMsg.rsp"])]
	public Task Shake256Messages(CavpRecord record)
	{
		return VerifyMessage<Shake256Core>(record);
	}

	[Test]
	[MethodDataSource(nameof(Records), Arguments = ["SHAKE128VariableOut.rsp"])]
	public Task Shake128VariableOutput(CavpRecord record)
	{
		return VerifyVariableOutput<Shake128Core>(record);
	}

	[Test]
	[MethodDataSource(nameof(Records), Arguments = ["SHAKE256VariableOut.rsp"])]
	public Task Shake256VariableOutput(CavpRecord record)
	{
		return VerifyVariableOutput<Shake256Core>(record);
	}

	[Test]
	public Task Shake128MonteCarlo()
	{
		return VerifyMonteCarlo<Shake128Core>("SHAKE128Monte.rsp");
	}

	[Test]
	public Task Shake256MonteCarlo()
	{
		return VerifyMonteCarlo<Shake256Core>("SHAKE256Monte.rsp");
	}

	// Guards the embedding and sampling: ShortMsg covers every message length from 0 to twice the rate, and Monte holds the message and its checkpoints.
	[Test]
	[Arguments("SHAKE128ShortMsg.rsp", 2 * 168 + 1)]
	[Arguments("SHAKE256ShortMsg.rsp", 2 * 136 + 1)]
	[Arguments("SHAKE128LongMsg.rsp", 14)]
	[Arguments("SHAKE256LongMsg.rsp", 14)]
	[Arguments("SHAKE128VariableOut.rsp", 143)]
	[Arguments("SHAKE256VariableOut.rsp", 157)]
	[Arguments("SHAKE128Monte.rsp", MonteCarloCheckpoints + 1)]
	[Arguments("SHAKE256Monte.rsp", MonteCarloCheckpoints + 1)]
	public async Task FilesHaveAllRecords(string fileName, int expectedCount)
	{
		await Assert.That(CavpRspFile.Load(fileName).Records).Count().IsEqualTo(expectedCount);
	}

	// The sampled variable-output files keep the shortest and longest outputs that the SHA3VS tested.
	[Test]
	[Arguments("SHAKE128VariableOut.rsp", 128, 1120)]
	[Arguments("SHAKE256VariableOut.rsp", 16, 2000)]
	public async Task VariableOutputKeepsExtremeLengths(string fileName, int minimumBits, int maximumBits)
	{
		int[] lengths = CavpRspFile.Load(fileName).Records.Select(static record => record.GetInt32("Outputlen")).ToArray();

		using (Assert.Multiple())
		{
			await Assert.That(lengths.Min()).IsEqualTo(minimumBits);
			await Assert.That(lengths.Max()).IsEqualTo(maximumBits);
		}
	}

	// The reference stands in for the platform where it lacks SHAKE, so it must itself pass the vectors.
	[Test]
	[Arguments("SHAKE128ShortMsg.rsp", 168)]
	[Arguments("SHAKE256ShortMsg.rsp", 136)]
	[Arguments("SHAKE128LongMsg.rsp", 168)]
	[Arguments("SHAKE256LongMsg.rsp", 136)]
	[Arguments("SHAKE128VariableOut.rsp", 168)]
	[Arguments("SHAKE256VariableOut.rsp", 136)]
	public async Task ReferenceMatchesVectors(string fileName, int rate)
	{
		foreach (CavpRecord record in CavpRspFile.Load(fileName).Records)
		{
			byte[] expected = record.GetBytes("Output");
			byte[] message = record.Contains("Len") ? record.GetMessage() : record.GetBytes("Msg");
			await Assert.That(KeccakReference.Sponge(message, rate, KeccakReference.ShakeDomainSeparator, expected.Length)).IsEquivalentTo(expected, CollectionOrdering.Matching);
		}
	}

	private static async Task VerifyMessage<T>(CavpRecord record) where T : unmanaged, IXofCore<T>
	{
		byte[] message = record.GetMessage();
		byte[] expected = record.GetBytes("Output");

		await Assert.That(expected.Length * 8).IsEqualTo(record.GetHeaderInt32("Outputlen"));
		await VerifyOutput<T>(message, expected);
	}

	private static async Task VerifyVariableOutput<T>(CavpRecord record) where T : unmanaged, IXofCore<T>
	{
		byte[] message = record.GetBytes("Msg");
		byte[] expected = record.GetBytes("Output");

		using (Assert.Multiple())
		{
			await Assert.That(message.Length * 8).IsEqualTo(record.GetHeaderInt32("Input Length"));
			await Assert.That(expected.Length * 8).IsEqualTo(record.GetInt32("Outputlen"));
		}

		await VerifyOutput<T>(message, expected);
	}

	private static async Task VerifyOutput<T>(byte[] message, byte[] expected) where T : unmanaged, IXofCore<T>
	{
		byte[] destination = new byte[expected.Length + 2];
		PrepareDestination(destination);
		Xof<T>.HashData(message, destination.AsSpan(1, expected.Length));
		await AssertOutput(destination, 1, expected);

		// Appends the input and reads the output in pieces of up to three blocks, which start and end at arbitrary offsets within blocks.
		using Xof<T> xof = Xof<T>.Create();
		uint state = (uint)message.Length;
		int maximumPieceLength = 3 * XofContractTest.BlockLength<Xof<T>>();

		for (int offset = 0; offset < message.Length;)
		{
			state = state * 1664525U + 1013904223U;
			int length = Math.Min((int)(state % (uint)maximumPieceLength) + 1, message.Length - offset);
			xof.Append(message.AsSpan(offset, length));
			offset += length;
		}

		PrepareDestination(destination);

		for (int offset = 0; offset < expected.Length;)
		{
			state = state * 1664525U + 1013904223U;
			int length = Math.Min((int)(state % (uint)maximumPieceLength), expected.Length - offset);
			xof.Read(destination.AsSpan(1 + offset, length));
			offset += length;
		}

		await AssertOutput(destination, 1, expected);
	}

	// SHA3VS, Sec. 6.3.3: each message is the leftmost 128 bits of the previous output, padded with zeros if shorter, and each output length after the
	// first is minoutbytes + (the rightmost 16 bits of the previous output mod (maxoutbytes - minoutbytes + 1)), in bytes; the first is maxoutbytes.
	// The minimum is rounded up and the maximum down to whole bytes. Every 1000th output is a checkpoint, and the chain carries on across checkpoints.
	private static async Task VerifyMonteCarlo<T>(string fileName) where T : unmanaged, IXofCore<T>
	{
		IReadOnlyList<CavpRecord> records = CavpRspFile.Load(fileName).Records;
		CavpRecord seed = records[0];
		int minimumOutputLength = (seed.GetHeaderInt32("Minimum Output Length (bits)") + 7) / 8;
		int maximumOutputLength = seed.GetHeaderInt32("Maximum Output Length (bits)") / 8;
		int range = maximumOutputLength - minimumOutputLength + 1;
		byte[] message = seed.GetBytes("Msg");
		byte[] output = new byte[maximumOutputLength];
		int outputLength = maximumOutputLength;

		await Assert.That(records).Count().IsEqualTo(MonteCarloCheckpoints + 1);
		await Assert.That(message.Length).IsEqualTo(MonteCarloMessageLength);

		for (int checkpoint = 0; checkpoint < MonteCarloCheckpoints; ++checkpoint)
		{
			int checkpointLength = 0;

			for (int i = 0; i < MonteCarloIterations; ++i)
			{
				Xof<T>.HashData(message, output.AsSpan(0, outputLength));
				checkpointLength = outputLength;

				message.AsSpan().Clear();
				output.AsSpan(0, Math.Min(outputLength, MonteCarloMessageLength)).CopyTo(message);
				int rightmostBits = BinaryPrimitives.ReadUInt16BigEndian(output.AsSpan(outputLength - sizeof(ushort)));
				outputLength = minimumOutputLength + rightmostBits % range;
			}

			CavpRecord record = records[checkpoint + 1];

			using (Assert.Multiple())
			{
				await Assert.That(record.GetInt32("COUNT")).IsEqualTo(checkpoint);
				await Assert.That(record.GetInt32("Outputlen")).IsEqualTo(checkpointLength * 8);
				await Assert.That(output.AsSpan(0, checkpointLength).ToArray()).IsEquivalentTo(record.GetBytes("Output"), CollectionOrdering.Matching);
			}
		}
	}
}
