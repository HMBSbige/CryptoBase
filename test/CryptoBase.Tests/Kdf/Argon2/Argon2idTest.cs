using CryptoBase.Kdf;
using CryptoBase.Kdf.Argon2;
using System.Text;

namespace CryptoBase.Tests.Kdf.Argon2;

[InheritsTests]
public class Argon2idTest() : Argon2DeriveKeyTest(Argon2Type.Argon2id)
{
	protected override void DeriveKey(ReadOnlySpan<byte> password, ReadOnlySpan<byte> salt, Span<byte> destination, Argon2Parameters parameters, ReadOnlySpan<byte> secret, ReadOnlySpan<byte> associatedData, int maxDegreeOfParallelism)
	{
		Argon2id.DeriveKey(password, salt, destination, parameters, secret, associatedData, maxDegreeOfParallelism);
	}

	[Test]
	public async Task Rfc9106Vector()
	{
		byte[] tag = new byte[32];
		Argon2id.DeriveKey(Fill(32, 0x01), Fill(16, 0x02), tag, new Argon2Parameters(memorySizeInKibibytes: 32, iterations: 3, parallelism: 4), Fill(8, 0x03), Fill(12, 0x04));

		await Assert.That(tag).IsEquivalentTo(Convert.FromHexString(@"0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659"), CollectionOrdering.Matching);
	}

	[Test]
	[Arguments("password", "somesalt", 2, 16, 1, @"09316115d5cf24ed5a15a31a3ba326e5cf32edc24702987c02b6566f61913cf7")]
	[Arguments("password", "somesalt", 2, 8, 1, @"9dfeb910e80bad0311fee20f9c0e2b12c17987b4cac90c2ef54d5b3021c68bfe")]
	[Arguments("password", "somesalt", 2, 8, 2, @"6d093c501fd5999645e0ea3bf620d7b8be7fd2db59c20d9fff9539da2bf57037")]
	public async Task ReferenceImplementationVector(string password, string salt, int iterations, int memoryExponent, int parallelism, string tagHex)
	{
		byte[] tag = new byte[32];
		Argon2id.DeriveKey(Encoding.UTF8.GetBytes(password), Encoding.UTF8.GetBytes(salt), tag, new Argon2Parameters(1 << memoryExponent, iterations, parallelism));

		await Assert.That(tag).IsEquivalentTo(Convert.FromHexString(tagHex), CollectionOrdering.Matching);
	}

	[Test]
	[Arguments(66000, 3, @"3286724bc8e762f816a043f16cb7da16264ef1455a5260355aae5447c0586fa1")]
	[Arguments(65536, 4, @"716733ba17477e10c0eac8788a61e795df9c5086d785b7de8e295b910fe9fd4a")]
	public async Task LargeMemoryVector(int memorySizeInKibibytes, int parallelism, string tagHex)
	{
		byte[] tag = new byte[32];
		Argon2id.DeriveKey("password"u8, "somesalt"u8, tag, new Argon2Parameters(memorySizeInKibibytes, 1, parallelism));

		await Assert.That(tag).IsEquivalentTo(Convert.FromHexString(tagHex), CollectionOrdering.Matching);
	}

	[Test]
	[Arguments(1, -1, 0)]
	[Arguments(1, 8, 0)]
	[Arguments(4, 1, 0)]
	[Arguments(4, 2, 1)]
	[Arguments(4, 4, 3)]
	[Arguments(4, int.MaxValue, 3)]
	public async Task HelperCountFollowsMaxDegreeOfParallelism(int lanes, int maxDegreeOfParallelism, int helpers)
	{
		await Assert.That(Argon2LaneScheduler.HelperCount(lanes, maxDegreeOfParallelism)).IsEqualTo(helpers);
	}

	[Test]
	public async Task UnlimitedHelperCountTakesOneThreadPerLaneUpToTheProcessors()
	{
		using (Assert.Multiple())
		{
			await Assert.That(Argon2LaneScheduler.HelperCount(4, -1)).IsEqualTo(Math.Min(4, Environment.ProcessorCount) - 1);
			await Assert.That(Argon2LaneScheduler.HelperCount((1 << 24) - 1, -1)).IsEqualTo(Environment.ProcessorCount - 1);
		}
	}

	[Test]
	[Arguments(16, 1, 0)]
	[Arguments(16, 1, -1)]
	[Arguments(int.MaxValue, 1, 1 << 24)]
	[Arguments(16, 0, 1)]
	[Arguments(7, 1, 1)]
	[Arguments(23, 1, 3)]
	[Arguments(-8, 1, 1)]
	public async Task ParametersRejectOutOfRangeValues(int memorySizeInKibibytes, int iterations, int parallelism)
	{
		await Assert.That(() => new Argon2Parameters(memorySizeInKibibytes, iterations, parallelism)).ThrowsExactly<ArgumentOutOfRangeException>();
	}

	[Test]
	public async Task ParametersAcceptBoundaryValues()
	{
		Argon2Parameters maximum = new(int.MaxValue, int.MaxValue, (1 << 24) - 1);

		using (Assert.Multiple())
		{
			await Assert.That(maximum.MemorySizeInKibibytes).IsEqualTo(int.MaxValue);
			await Assert.That(maximum.Iterations).IsEqualTo(int.MaxValue);
			await Assert.That(maximum.Parallelism).IsEqualTo((1 << 24) - 1);
		}
	}
}
