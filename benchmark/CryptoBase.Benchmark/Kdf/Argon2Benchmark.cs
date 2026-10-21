using BenchmarkDotNet.Attributes;
using CryptoBase.Kdf;
using Org.BouncyCastle.Crypto.Generators;
using System.Security.Cryptography;
using BouncyCastleArgon2Parameters = Org.BouncyCastle.Crypto.Parameters.Argon2Parameters;

namespace CryptoBase.Benchmark.Kdf;

public class Argon2dBenchmark() : Argon2Benchmark(BouncyCastleArgon2Parameters.Argon2d)
{
	[Benchmark(Baseline = true)]
	public override void CryptoBase()
	{
		Argon2d.DeriveKey(Password, Salt, Tag, Parameters);
	}
}

public class Argon2iBenchmark() : Argon2Benchmark(BouncyCastleArgon2Parameters.Argon2i)
{
	[Benchmark(Baseline = true)]
	public override void CryptoBase()
	{
		Argon2i.DeriveKey(Password, Salt, Tag, Parameters);
	}
}

public class Argon2idBenchmark() : Argon2Benchmark(BouncyCastleArgon2Parameters.Argon2id)
{
	[Benchmark(Baseline = true)]
	public override void CryptoBase()
	{
		Argon2id.DeriveKey(Password, Salt, Tag, Parameters);
	}
}

[MemoryDiagnoser]
public abstract class Argon2Benchmark(int bouncyCastleType)
{
	private BouncyCastleArgon2Parameters _bouncyCastleParameters = null!;

	protected byte[] Password { get; private set; } = [];

	protected byte[] Salt { get; private set; } = [];

	protected byte[] Tag { get; private set; } = [];

	protected Argon2Parameters Parameters { get; private set; }

	[Params("19456,2,1", "65536,3,1", "65536,3,4")]
	public string Cost { get; set; } = "";

	[GlobalSetup]
	public void Setup()
	{
		int[] cost = Cost.Split(',').Select(int.Parse).ToArray();
		Parameters = new Argon2Parameters(cost[0], cost[1], cost[2]);
		Password = RandomNumberGenerator.GetBytes(32);
		Salt = RandomNumberGenerator.GetBytes(16);
		Tag = new byte[32];
		_bouncyCastleParameters = new BouncyCastleArgon2Parameters.Builder(bouncyCastleType)
			.WithVersion(BouncyCastleArgon2Parameters.Version13)
			.WithMemoryAsKB(cost[0])
			.WithIterations(cost[1])
			.WithParallelism(cost[2])
			.WithSalt(Salt)
			.Build();

		BouncyCastle();
		byte[] expected = (byte[])Tag.Clone();
		CryptoBase();

		if (!CryptographicOperations.FixedTimeEquals(expected, Tag))
		{
			throw new InvalidOperationException("Benchmark implementations produced different tags.");
		}
	}

	public abstract void CryptoBase();

	[Benchmark]
	public int BouncyCastle()
	{
		Argon2BytesGenerator generator = new();
		generator.Init(_bouncyCastleParameters);
		return generator.GenerateBytes(Password, Tag);
	}
}
