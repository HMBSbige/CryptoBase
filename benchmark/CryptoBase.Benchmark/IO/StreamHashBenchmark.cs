using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Configs;
using CryptoBase.Hashes;
using CryptoBase.Hashes.Sha2;
using CryptoBase.IO;
using System.Buffers.Binary;
using System.Security.Cryptography;

namespace CryptoBase.Benchmark.IO;

[MemoryDiagnoser]
[CategoriesColumn]
[GroupBenchmarksBy(BenchmarkLogicalGroupRule.ByCategory)]
public class StreamHashBenchmark
{
	[Params(0, 4095, 4096, 4097, 64 * 1024, 1024 * 1024)]
	public int ByteLength { get; set; }

	private MemoryStream _stream = null!;
	private byte[] _hash = null!;
	private HashAlgorithm<Sha256Core> _hasher = null!;

	[GlobalSetup]
	public void Setup()
	{
		_stream = new MemoryStream(RandomNumberGenerator.GetBytes(ByteLength), false);
		_hash = GC.AllocateUninitializedArray<byte>(HashAlgorithm<Sha256Core>.HashLength);
		_hasher = HashAlgorithm<Sha256Core>.Create();
	}

	[GlobalCleanup]
	public void Cleanup()
	{
		_stream.Dispose();
		_hasher.Dispose();
	}

	[Benchmark(Baseline = true)]
	[BenchmarkCategory("Sync")]
	public uint CryptoBaseSync()
	{
		_stream.Position = 0;
		Span<byte> hash = stackalloc byte[HashAlgorithm<Sha256Core>.HashLength];
		_ = HashAlgorithm<Sha256Core>.HashData(_stream, hash);
		return BinaryPrimitives.ReadUInt32LittleEndian(hash);
	}

	[Benchmark]
	[BenchmarkCategory("Sync")]
	public uint BclSync()
	{
		_stream.Position = 0;
		Span<byte> hash = stackalloc byte[HashAlgorithm<Sha256Core>.HashLength];
		_ = SHA256.HashData(_stream, hash);
		return BinaryPrimitives.ReadUInt32LittleEndian(hash);
	}

	[Benchmark]
	[BenchmarkCategory("Sync")]
	public uint CryptoBaseInstanceSync()
	{
		_stream.Position = 0;
		Span<byte> hash = stackalloc byte[HashAlgorithm<Sha256Core>.HashLength];
		_hasher.Append(_stream);
		_ = _hasher.GetHashAndReset(hash);
		return BinaryPrimitives.ReadUInt32LittleEndian(hash);
	}

	[Benchmark(Baseline = true)]
	[BenchmarkCategory("Async")]
	public ValueTask<int> CryptoBaseAsync()
	{
		_stream.Position = 0;
		return HashAlgorithm<Sha256Core>.HashDataAsync(_stream, _hash);
	}

	[Benchmark]
	[BenchmarkCategory("Async")]
	public ValueTask<int> BclAsync()
	{
		_stream.Position = 0;
		return SHA256.HashDataAsync(_stream, _hash);
	}
}
