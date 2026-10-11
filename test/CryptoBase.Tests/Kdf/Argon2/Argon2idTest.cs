using CryptoBase.Kdf;
using CryptoBase.Kdf.Argon2;
using System.Text;
using static CryptoBase.Tests.TestUtils;

namespace CryptoBase.Tests.Kdf.Argon2;

public class Argon2idTest
{
	public static IEnumerable<Func<Argon2Case>> Cases()
	{
		yield return () => new Argon2Case(8, 1, 1, 32, 0, 0, 0, 0);
		yield return () => new Argon2Case(9, 1, 1, 4, 1, 8, 0, 0);
		yield return () => new Argon2Case(16, 2, 2, 64, 13, 16, 0, 0);
		yield return () => new Argon2Case(37, 3, 3, 65, 5, 16, 32, 7);
		yield return () => new Argon2Case(64, 1, 4, 97, 32, 16, 8, 12);
		yield return () => new Argon2Case(100, 2, 5, 128, 7, 9, 1, 1);
		yield return () => new Argon2Case(520, 1, 1, 33, 16, 16, 0, 0);
		yield return () => new Argon2Case(300, 3, 1, 48, 12, 16, 0, 0);
		yield return () => new Argon2Case(1040, 2, 2, 1500, 8, 16, 16, 16);
		yield return () => new Argon2Case(840, 2, 3, 31, 24, 16, 0, 40);
		yield return () => new Argon2Case(1024, 2, 4, 32, 64, 32, 0, 0);
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
	[MethodDataSource(nameof(Cases))]
	public async Task EveryKernelMatchesReference(Argon2Case testCase)
	{
		byte[] expected = testCase.ComputeReference();

		using (Assert.Multiple())
		{
			foreach (Argon2KernelCase kernel in Argon2KernelCase.All().Where(static kernel => kernel.IsSupported))
			{
				await Assert.That(Derive(kernel, testCase)).IsEquivalentTo(expected, CollectionOrdering.Matching).Because(kernel.ToString());
			}
		}
	}

	[Test]
	public async Task ConcurrentDerivationsWithManyLanesMatchReference()
	{
		Argon2Case[] cases =
		[
			new(32, 2, 4, 32, 8, 16, 0, 0),
			new(256, 1, 8, 32, 9, 16, 0, 0),
			new(240, 2, 3, 32, 10, 16, 0, 0),
			new(512, 1, 16, 32, 11, 16, 0, 0)
		];
		byte[][] expected = cases.Select(static testCase => testCase.ComputeReference()).ToArray();
		byte[][] actual = new byte[cases.Length * 8][];

		await Parallel.ForAsync
		(
			0, actual.Length, (i, _) =>
			{
				Argon2Case testCase = cases[i % cases.Length];
				actual[i] = new byte[testCase.TagLength];
				Argon2id.DeriveKey(testCase.Password, testCase.Salt, actual[i], testCase.Parameters);
				return ValueTask.CompletedTask;
			}
		);

		using (Assert.Multiple())
		{
			for (int i = 0; i < actual.Length; ++i)
			{
				await Assert.That(actual[i]).IsEquivalentTo(expected[i % cases.Length], CollectionOrdering.Matching);
			}
		}
	}

	[Test]
	public async Task SupportsOverlappingInputsAndDestination()
	{
		byte[] password = CreateDeterministicSource(40);
		byte[] salt = CreateDeterministicSource(16);
		byte[] secret = CreateDeterministicSource(24);
		byte[] associatedData = CreateDeterministicSource(12);
		Argon2Parameters parameters = new(32, 1, 2);
		byte[] expected = new byte[48];
		Argon2id.DeriveKey(password, salt, expected, parameters, secret, associatedData);

		foreach (int offset in new[] { 0, 7, 20 })
		{
			byte[] buffer = new byte[offset + Math.Max(password.Length, expected.Length)];
			password.CopyTo(buffer, offset);
			Span<byte> passwordSpan = buffer.AsSpan(offset, password.Length);
			Argon2id.DeriveKey(passwordSpan, salt, buffer.AsSpan(0, expected.Length), parameters, secret, associatedData);

			await Assert.That(buffer.AsMemory(0, expected.Length)).IsEquivalentTo(expected, CollectionOrdering.Matching);
		}

		byte[] shared = (byte[])salt.Clone();
		Array.Resize(ref shared, expected.Length);
		Argon2id.DeriveKey(password, shared.AsSpan(0, salt.Length), shared, parameters, secret, associatedData);

		await Assert.That(shared).IsEquivalentTo(expected, CollectionOrdering.Matching);
	}

	[Test]
	public async Task RejectsInvalidArgumentsWithoutWriting()
	{
		byte[] password = CreateDeterministicSource(8);
		byte[] salt = CreateDeterministicSource(16);
		byte[] shortDestination = new byte[3];
		PrepareDestination(shortDestination);
		byte[] destination = new byte[32];
		PrepareDestination(destination);

		await Assert.That(() => Argon2id.DeriveKey(password, salt, shortDestination, new Argon2Parameters(8, 1, 1)))
			.ThrowsExactly<ArgumentOutOfRangeException>();
		await Assert.That(shortDestination).All(static value => value is DestinationSentinel);

		await Assert.That(() => Argon2id.DeriveKey(password, salt, destination, default))
			.ThrowsExactly<ArgumentException>();
		await Assert.That(destination).All(static value => value is DestinationSentinel);
	}

	[Test]
	[Arguments(0)]
	[Arguments(-2)]
	public async Task RejectsInvalidMaxDegreeOfParallelismWithoutWriting(int maxDegreeOfParallelism)
	{
		byte[] destination = new byte[32];
		PrepareDestination(destination);

		await Assert.That(() => Argon2id.DeriveKey(CreateDeterministicSource(8), CreateDeterministicSource(16), destination, new Argon2Parameters(32, 1, 4), maxDegreeOfParallelism: maxDegreeOfParallelism))
			.ThrowsExactly<ArgumentOutOfRangeException>().WithParameterName("maxDegreeOfParallelism");
		await Assert.That(destination).All(static value => value is DestinationSentinel);
	}

	[Test]
	[Arguments(-1)]
	[Arguments(1)]
	[Arguments(2)]
	[Arguments(3)]
	[Arguments(5)]
	public async Task MaxDegreeOfParallelismDoesNotChangeTheKey(int maxDegreeOfParallelism)
	{
		Argon2Case[] cases =
		[
			new(32, 3, 4, 32, 8, 16, 8, 12),
			new(240, 2, 3, 32, 10, 16, 0, 0),
			new(100, 2, 5, 64, 7, 9, 1, 1)
		];

		using (Assert.Multiple())
		{
			foreach (Argon2Case testCase in cases)
			{
				byte[] actual = new byte[testCase.TagLength];
				Argon2id.DeriveKey(testCase.Password, testCase.Salt, actual, testCase.Parameters, testCase.Secret, testCase.AssociatedData, maxDegreeOfParallelism);

				await Assert.That(actual).IsEquivalentTo(testCase.ComputeReference(), CollectionOrdering.Matching);
			}
		}
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

	private static byte[] Derive(Argon2KernelCase kernel, Argon2Case testCase)
	{
		byte[] tag = new byte[testCase.TagLength];
		kernel.DeriveKey(testCase.Password, testCase.Salt, testCase.Secret, testCase.AssociatedData, testCase.Parameters, tag);
		return tag;
	}

	private static byte[] Fill(int length, byte value)
	{
		return Enumerable.Repeat(value, length).ToArray();
	}

	public sealed record Argon2Case(int MemorySize, int Iterations, int Parallelism, int TagLength, int PasswordLength, int SaltLength, int SecretLength, int AssociatedDataLength)
	{
		public byte[] Password { get; } = CreateDeterministicSource(PasswordLength);

		public byte[] Salt { get; } = CreateDeterministicSource(SaltLength).Reverse().ToArray();

		public byte[] Secret { get; } = Fill(SecretLength, 0x5C);

		public byte[] AssociatedData { get; } = Fill(AssociatedDataLength, 0x36);

		public Argon2Parameters Parameters => new(MemorySize, Iterations, Parallelism);

		public byte[] ComputeReference()
		{
			return Argon2Reference.Argon2id(Password, Salt, Secret, AssociatedData, MemorySize, Iterations, Parallelism, TagLength);
		}

		public override string ToString()
		{
			return $"m={MemorySize},t={Iterations},p={Parallelism},T={TagLength},P={PasswordLength},S={SaltLength},K={SecretLength},X={AssociatedDataLength}";
		}
	}
}
