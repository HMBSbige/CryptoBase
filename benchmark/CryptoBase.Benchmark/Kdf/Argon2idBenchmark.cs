using BenchmarkDotNet.Attributes;
using CryptoBase.Kdf;
using Org.BouncyCastle.Crypto.Generators;
using System.Security.Cryptography;
using BouncyCastleArgon2Parameters = Org.BouncyCastle.Crypto.Parameters.Argon2Parameters;

namespace CryptoBase.Benchmark.Kdf;

[MemoryDiagnoser]
public class Argon2idBenchmark
{
	private byte[] _password = [];
	private byte[] _salt = [];
	private byte[] _tag = [];
	private Argon2Parameters _parameters;
	private BouncyCastleArgon2Parameters _bouncyCastleParameters = null!;

	[Params("19456,2,1", "65536,3,1", "65536,3,4")]
	public string Cost { get; set; } = "";

	[GlobalSetup]
	public void Setup()
	{
		int[] cost = Cost.Split(',').Select(int.Parse).ToArray();
		_parameters = new Argon2Parameters(cost[0], cost[1], cost[2]);
		_password = RandomNumberGenerator.GetBytes(32);
		_salt = RandomNumberGenerator.GetBytes(16);
		_tag = new byte[32];
		_bouncyCastleParameters = new BouncyCastleArgon2Parameters.Builder(BouncyCastleArgon2Parameters.Argon2id)
			.WithVersion(BouncyCastleArgon2Parameters.Version13)
			.WithMemoryAsKB(cost[0])
			.WithIterations(cost[1])
			.WithParallelism(cost[2])
			.WithSalt(_salt)
			.Build();

		BouncyCastle();
		byte[] expected = (byte[])_tag.Clone();
		CryptoBase();

		if (!CryptographicOperations.FixedTimeEquals(expected, _tag))
		{
			throw new InvalidOperationException("Benchmark implementations produced different tags.");
		}
	}

	[Benchmark(Baseline = true)]
	public void CryptoBase()
	{
		Argon2id.DeriveKey(_password, _salt, _tag, _parameters);
	}

	[Benchmark]
	public int BouncyCastle()
	{
		Argon2BytesGenerator generator = new();
		generator.Init(_bouncyCastleParameters);
		return generator.GenerateBytes(_password, _tag);
	}
}
