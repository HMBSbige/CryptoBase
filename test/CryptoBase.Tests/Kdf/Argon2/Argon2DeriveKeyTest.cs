using CryptoBase.Kdf;
using static CryptoBase.Tests.TestUtils;

namespace CryptoBase.Tests.Kdf.Argon2;

public abstract class Argon2DeriveKeyTest(Argon2Type type)
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

	public static IEnumerable<Func<Argon2Case>> ParallelismCases()
	{
		yield return () => new Argon2Case(32, 3, 4, 32, 8, 16, 8, 12);
		yield return () => new Argon2Case(240, 2, 3, 32, 10, 16, 0, 0);
		yield return () => new Argon2Case(100, 2, 5, 64, 7, 9, 1, 1);
	}

	protected abstract void DeriveKey(ReadOnlySpan<byte> password, ReadOnlySpan<byte> salt, Span<byte> destination, Argon2Parameters parameters, ReadOnlySpan<byte> secret, ReadOnlySpan<byte> associatedData, int maxDegreeOfParallelism);

	// https://www.rfc-editor.org/rfc/rfc9106#section-5
	[Test]
	public async Task Rfc9106Vector()
	{
		string expected = type switch
		{
			Argon2Type.Argon2d => @"512b391b6f1162975371d30919734294f868e3be3984f3c1a13a4db9fabe4acb",
			Argon2Type.Argon2i => @"c814d9d1dc7f37aa13f0d77f2494bda1c8de6b016dd388d29952a4c4672b6ce8",
			Argon2Type.Argon2id => @"0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659",
			_ => throw new ArgumentOutOfRangeException(nameof(type))
		};
		byte[] tag = new byte[32];
		DeriveKey(Fill(32, 0x01), Fill(16, 0x02), tag, new Argon2Parameters(memorySizeInKibibytes: 32, iterations: 3, parallelism: 4), Fill(8, 0x03), Fill(12, 0x04), -1);

		await Assert.That(tag).IsEquivalentTo(Convert.FromHexString(expected), CollectionOrdering.Matching);
	}

	[Test]
	[MethodDataSource(nameof(Cases))]
	public async Task EveryKernelMatchesReference(Argon2Case testCase)
	{
		byte[] expected = testCase.ComputeReference(type);

		using (Assert.Multiple())
		{
			foreach (Argon2KernelCase kernel in Argon2KernelCase.All().Where(static kernel => kernel.IsSupported))
			{
				byte[] tag = new byte[testCase.TagLength];
				kernel.DeriveKey(testCase.Password, testCase.Salt, testCase.Secret, testCase.AssociatedData, type, testCase.Parameters, tag);

				await Assert.That(tag).IsEquivalentTo(expected, CollectionOrdering.Matching).Because(kernel.ToString());
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
		byte[][] expected = cases.Select(testCase => testCase.ComputeReference(type)).ToArray();
		byte[][] actual = new byte[cases.Length * 8][];

		await Parallel.ForAsync
		(
			0, actual.Length, (i, _) =>
			{
				Argon2Case testCase = cases[i % cases.Length];
				actual[i] = new byte[testCase.TagLength];
				DeriveKey(testCase.Password, testCase.Salt, actual[i], testCase.Parameters, default, default, -1);
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
		DeriveKey(password, salt, expected, parameters, secret, associatedData, -1);

		foreach (int offset in new[] { 0, 7, 20 })
		{
			byte[] buffer = new byte[offset + Math.Max(password.Length, expected.Length)];
			password.CopyTo(buffer, offset);
			Span<byte> passwordSpan = buffer.AsSpan(offset, password.Length);
			DeriveKey(passwordSpan, salt, buffer.AsSpan(0, expected.Length), parameters, secret, associatedData, -1);

			await Assert.That(buffer.AsMemory(0, expected.Length)).IsEquivalentTo(expected, CollectionOrdering.Matching);
		}

		byte[] shared = (byte[])salt.Clone();
		Array.Resize(ref shared, expected.Length);
		DeriveKey(password, shared.AsSpan(0, salt.Length), shared, parameters, secret, associatedData, -1);

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

		await Assert.That(() => DeriveKey(password, salt, shortDestination, new Argon2Parameters(8, 1, 1), default, default, -1))
			.ThrowsExactly<ArgumentOutOfRangeException>().WithParameterName("destination");
		await Assert.That(shortDestination).All(static value => value is DestinationSentinel);

		await Assert.That(() => DeriveKey(password, salt, destination, default, default, default, -1))
			.ThrowsExactly<ArgumentException>().WithParameterName("parameters");
		await Assert.That(destination).All(static value => value is DestinationSentinel);
	}

	[Test]
	[Arguments(0)]
	[Arguments(-2)]
	public async Task RejectsInvalidMaxDegreeOfParallelismWithoutWriting(int maxDegreeOfParallelism)
	{
		byte[] destination = new byte[32];
		PrepareDestination(destination);

		await Assert.That(() => DeriveKey(CreateDeterministicSource(8), CreateDeterministicSource(16), destination, new Argon2Parameters(32, 1, 4), default, default, maxDegreeOfParallelism))
			.ThrowsExactly<ArgumentOutOfRangeException>().WithParameterName("maxDegreeOfParallelism");
		await Assert.That(destination).All(static value => value is DestinationSentinel);
	}

	[Test]
	[MethodDataSource(nameof(ParallelismCases))]
	public async Task MaxDegreeOfParallelismDoesNotChangeTheKey(Argon2Case testCase)
	{
		byte[] expected = testCase.ComputeReference(type);

		using (Assert.Multiple())
		{
			foreach (int maxDegreeOfParallelism in new[] { -1, 1, 2, 3, 5 })
			{
				byte[] actual = new byte[testCase.TagLength];
				DeriveKey(testCase.Password, testCase.Salt, actual, testCase.Parameters, testCase.Secret, testCase.AssociatedData, maxDegreeOfParallelism);

				await Assert.That(actual).IsEquivalentTo(expected, CollectionOrdering.Matching).Because($"maxDegreeOfParallelism = {maxDegreeOfParallelism}");
			}
		}
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

		public byte[] ComputeReference(Argon2Type type)
		{
			return Argon2Reference.Derive(type, Password, Salt, Secret, AssociatedData, MemorySize, Iterations, Parallelism, TagLength);
		}

		public override string ToString()
		{
			return $"m={MemorySize},t={Iterations},p={Parallelism},T={TagLength},P={PasswordLength},S={SaltLength},K={SecretLength},X={AssociatedDataLength}";
		}
	}
}
