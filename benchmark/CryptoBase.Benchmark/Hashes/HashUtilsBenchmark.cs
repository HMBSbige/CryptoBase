using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Configs;
using CryptoBase.Hashes;
using CryptoBase.Hashes.Sha256;
using System.Buffers.Binary;
using System.Security.Cryptography;

namespace CryptoBase.Benchmark.Hashes;

[MemoryDiagnoser]
[CategoriesColumn]
[GroupBenchmarksBy(BenchmarkLogicalGroupRule.ByCategory)]
public class HashUtilsBenchmark
{
	[Params(0, 4095, 4096, 4097, 64 * 1024, 1024 * 1024)]
	public int ByteLength { get; set; }

	private MemoryStream _stream = null!;
	private byte[] _hash = null!;

	[GlobalSetup]
	public void Setup()
	{
		_stream = new MemoryStream
		(RandomNumberGenerator.GetBytes(ByteLength), false);
		_hash = GC.AllocateUninitializedArray<byte>(HashAlgorithm<Sha256HashAlgorithm>.HashLength);
	}

	[GlobalCleanup]
	public void Cleanup()
	{
		_stream.Dispose();
	}

	[Benchmark(Baseline = true)]
	[BenchmarkCategory("Sync")]
	public uint CryptoBaseSync()
	{
		_stream.Position = 0;
		Span<byte> hash = stackalloc byte[HashAlgorithm<Sha256HashAlgorithm>.HashLength];
		_ = _stream.ComputeHash<HashAlgorithm<Sha256HashAlgorithm>>(hash);
		return BinaryPrimitives.ReadUInt32LittleEndian(hash);
	}

	[Benchmark]
	[BenchmarkCategory("Sync")]
	public uint BclSync()
	{
		_stream.Position = 0;
		Span<byte> hash = stackalloc byte[HashAlgorithm<Sha256HashAlgorithm>.HashLength];
		_ = SHA256.HashData(_stream, hash);
		return BinaryPrimitives.ReadUInt32LittleEndian(hash);
	}

	[Benchmark(Baseline = true)]
	[BenchmarkCategory("Async")]
	public ValueTask<int> CryptoBaseAsync()
	{
		_stream.Position = 0;
		return _stream.ComputeHashAsync<HashAlgorithm<Sha256HashAlgorithm>>(_hash);
	}

	[Benchmark]
	[BenchmarkCategory("Async")]
	public ValueTask<int> BclAsync()
	{
		_stream.Position = 0;
		return SHA256.HashDataAsync(_stream, _hash);
	}
}
