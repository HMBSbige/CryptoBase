using BenchmarkDotNet.Attributes;
using CryptoBase.Abstractions.Hashes;
using CryptoBase.Hashes;
using Org.BouncyCastle.Crypto;
using System.Security.Cryptography;

namespace CryptoBase.Benchmark.Hashes;

public static class HashBenchmarkSizes
{
	public static IReadOnlyList<int> Block64 { get; } = [0, 55, 56, 64, 256, 1024, 8192, 1024 * 1024];

	public static IReadOnlyList<int> Block128 { get; } = [0, 111, 112, 128, 256, 1024, 8192, 1024 * 1024];

	// Inputs of 20, 32 and 64 bytes are the sizes of common keys and digests. A sponge pads in place: rate - 1 bytes still fit one block, while a full rate needs a second permutation.
	public static IReadOnlyList<int> Rate72 { get; } = [0, 20, 32, 64, 71, 72, 256, 1024, 8192, 1024 * 1024];

	public static IReadOnlyList<int> Rate104 { get; } = [0, 20, 32, 64, 103, 104, 256, 1024, 8192, 1024 * 1024];

	public static IReadOnlyList<int> Rate136 { get; } = [0, 20, 32, 64, 135, 136, 256, 1024, 8192, 1024 * 1024];

	public static IReadOnlyList<int> Rate144 { get; } = [0, 20, 32, 64, 143, 144, 256, 1024, 8192, 1024 * 1024];

	public static IReadOnlyList<int> Rate168 { get; } = [0, 20, 32, 64, 167, 168, 256, 1024, 8192, 1024 * 1024];
}

public abstract class BouncyCastleHashBenchmark<TCryptoBase, TBouncyCastle>
	where TCryptoBase : unmanaged, IHashCore<TCryptoBase>
	where TBouncyCastle : IDigest, new()
{
	[ParamsSource(nameof(ByteLengths))]
	public int ByteLength { get; set; }

	public IEnumerable<int> ByteLengths => Sizes;

	protected abstract IReadOnlyList<int> Sizes { get; }

	protected byte[] Input { get; private set; } = [];

	protected byte[] Hash { get; private set; } = [];

	private readonly TBouncyCastle _bouncyCastle = new();

	[GlobalSetup]
	public void Setup()
	{
		Input = RandomNumberGenerator.GetBytes(ByteLength);
		Hash = new byte[HashAlgorithm<TCryptoBase>.HashLength];

		BouncyCastle();
		byte[] expected = (byte[])Hash.Clone();
		CryptoBase();
		Verify(expected, Hash);
		VerifyAdditionalCompetitors(expected);
	}

	[Benchmark(Baseline = true)]
	public int CryptoBase()
	{
		return HashAlgorithm<TCryptoBase>.HashData(Input, Hash);
	}

	[Benchmark]
	public int BouncyCastle()
	{
		_bouncyCastle.BlockUpdate(Input);
		return _bouncyCastle.DoFinal(Hash);
	}

	protected virtual void VerifyAdditionalCompetitors(ReadOnlySpan<byte> expected)
	{
	}

	protected static void Verify(ReadOnlySpan<byte> expected, ReadOnlySpan<byte> actual)
	{
		if (!CryptographicOperations.FixedTimeEquals(expected, actual))
		{
			throw new InvalidOperationException("Benchmark implementations produced different hashes.");
		}
	}
}

public abstract class BclAndBouncyCastleHashBenchmark<TCryptoBase, TBcl, TBouncyCastle>
	: BouncyCastleHashBenchmark<TCryptoBase, TBouncyCastle>
	where TCryptoBase : unmanaged, IHashCore<TCryptoBase>
	where TBcl : IBclHashAlgorithm
	where TBouncyCastle : IDigest, new()
{
	[Benchmark]
	public int Bcl()
	{
		return TBcl.HashData(Input, Hash);
	}

	// Where the platform lacks the algorithm, Bcl throws PlatformNotSupportedException and reports no result, while the other columns still run.
	protected override void VerifyAdditionalCompetitors(ReadOnlySpan<byte> expected)
	{
		if (!TBcl.IsSupported)
		{
			return;
		}

		Bcl();
		Verify(expected, Hash);
	}
}
