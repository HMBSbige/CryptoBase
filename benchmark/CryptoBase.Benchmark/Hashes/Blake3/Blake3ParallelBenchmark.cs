using BenchmarkDotNet.Attributes;
using CryptoBase.Hashes.Blake3;
using System.Security.Cryptography;

namespace CryptoBase.Benchmark.Hashes.Blake3;

[MemoryDiagnoser]
public class Blake3ParallelBenchmark
{
	// The first append stays in the group buffer, so that the parallel append fills it and hashes it on the calling thread while pool threads start on the rest.
	private const int HeadLength = 3 * 1024 + 5;

	private readonly byte[] _hash = new byte[Blake3HashAlgorithm.HashLength];
	private readonly Blake3HashAlgorithm _hasher = Blake3HashAlgorithm.Create();
	private byte[] _input = [];
	private byte[] _output = [];

	[Params(256 * 1024, 1024 * 1024, 16 * 1024 * 1024)]
	public int ByteLength { get; set; }

	[Params(1, 2, 4, 8, -1)] public int MaxDegreeOfParallelism { get; set; }

	[GlobalSetup]
	public void Setup()
	{
		_input = RandomNumberGenerator.GetBytes(ByteLength);
		_output = new byte[ByteLength];
	}

	[GlobalCleanup]
	public void Cleanup()
	{
		_hasher.Dispose();
	}

	[Benchmark]
	public void Hash()
	{
		Blake3HashAlgorithm.HashData(_input, _hash, MaxDegreeOfParallelism);
	}

	[Benchmark]
	public void Append()
	{
		_hasher.Reset();
		_hasher.Append(_input.AsSpan(0, HeadLength));
		_hasher.Append(_input.AsSpan(HeadLength), MaxDegreeOfParallelism);
		_hasher.GetCurrentHash(_hash);
	}

	[Benchmark]
	public void ExtendedOutput()
	{
		Blake3HashAlgorithm.HashData(_hash, _output, MaxDegreeOfParallelism);
	}
}
