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

	private TBouncyCastle _bouncyCastle = default!;

	[GlobalSetup]
	public void Setup()
	{
		_bouncyCastle = new TBouncyCastle();
		Input = RandomNumberGenerator.GetBytes(ByteLength);
		Hash = new byte[HashAlgorithm<TCryptoBase>.HashLengthInBytes];

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

	protected override void VerifyAdditionalCompetitors(ReadOnlySpan<byte> expected)
	{
		Bcl();
		Verify(expected, Hash);
	}
}
