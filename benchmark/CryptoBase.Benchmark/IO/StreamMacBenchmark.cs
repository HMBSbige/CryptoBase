using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Configs;
using CryptoBase.Hashes.Sha2;
using CryptoBase.IO;
using CryptoBase.Macs.Hmac;
using System.Buffers.Binary;
using System.Security.Cryptography;

namespace CryptoBase.Benchmark.IO;

[MemoryDiagnoser]
[CategoriesColumn]
[GroupBenchmarksBy(BenchmarkLogicalGroupRule.ByCategory)]
public class StreamMacBenchmark
{
	[Params(0, 4095, 4096, 4097, 64 * 1024, 1024 * 1024)]
	public int ByteLength { get; set; }

	private byte[] _key = null!;
	private MemoryStream _stream = null!;
	private byte[] _mac = null!;

	[GlobalSetup]
	public void Setup()
	{
		_key = RandomNumberGenerator.GetBytes(32);
		_stream = new MemoryStream(RandomNumberGenerator.GetBytes(ByteLength), false);
		_mac = GC.AllocateUninitializedArray<byte>(HmacAlgorithm<Sha256HashAlgorithm>.MacLength);
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
		Span<byte> mac = stackalloc byte[HmacAlgorithm<Sha256HashAlgorithm>.MacLength];
		_ = HmacAlgorithm<Sha256HashAlgorithm>.MacData(_key, _stream, mac);
		return BinaryPrimitives.ReadUInt32LittleEndian(mac);
	}

	[Benchmark]
	[BenchmarkCategory("Sync")]
	public uint BclSync()
	{
		_stream.Position = 0;
		Span<byte> mac = stackalloc byte[HmacAlgorithm<Sha256HashAlgorithm>.MacLength];
		_ = HMACSHA256.HashData(_key, _stream, mac);
		return BinaryPrimitives.ReadUInt32LittleEndian(mac);
	}

	[Benchmark(Baseline = true)]
	[BenchmarkCategory("Async")]
	public ValueTask<int> CryptoBaseAsync()
	{
		_stream.Position = 0;
		return HmacAlgorithm<Sha256HashAlgorithm>.MacDataAsync(_key, _stream, _mac);
	}

	[Benchmark]
	[BenchmarkCategory("Async")]
	public ValueTask<int> BclAsync()
	{
		_stream.Position = 0;
		return HMACSHA256.HashDataAsync(_key, _stream, _mac);
	}
}
