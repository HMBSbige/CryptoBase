using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Configs;
using CryptoBase.Ciphers.Blocks.Aes;
using CryptoBase.Ciphers.Modes;
using CryptoBase.Hashes;
using CryptoBase.Hashes.Sha2;
using CryptoBase.IO;
using System.Security.Cryptography;

namespace CryptoBase.Benchmark.IO;

[MemoryDiagnoser]
[CategoriesColumn]
[GroupBenchmarksBy(BenchmarkLogicalGroupRule.ByCategory)]
public class StreamByteBenchmark
{
	private const int ByteCount = 4096;
	private const int DataUnitSize = 512;

	private MemoryStream _memoryStream = null!;
	private MemoryStream _hashInner = null!;
	private HashStream<HashAlgorithm<Sha256Core>> _hashStream = null!;
	private DataUnitStream<XtsMode<AesCipher>> _dataUnitStream = null!;

	[GlobalSetup]
	public void Setup()
	{
		byte[] data = RandomNumberGenerator.GetBytes(ByteCount);

		_memoryStream = new MemoryStream(ByteCount);
		_memoryStream.Write(data);

		_hashInner = new MemoryStream(ByteCount);
		_hashInner.Write(data);
		_hashStream = HashStream.Create(_hashInner, HashAlgorithm<Sha256Core>.Create());

		_dataUnitStream = DataUnitStream.Create(new MemoryStream(ByteCount), XtsBenchmarkData.CreateCipher(), DataUnitSize);
		_dataUnitStream.Write(data);
		_dataUnitStream.Flush();
	}

	[GlobalCleanup]
	public void Cleanup()
	{
		_memoryStream.Dispose();
		_hashStream.Dispose();
		_dataUnitStream.Dispose();
	}

	[Benchmark(Baseline = true, OperationsPerInvoke = ByteCount)]
	[BenchmarkCategory("ReadByte")]
	public int MemoryStreamReadByte()
	{
		_memoryStream.Position = 0;
		return ReadBytes(_memoryStream);
	}

	[Benchmark(OperationsPerInvoke = ByteCount)]
	[BenchmarkCategory("ReadByte")]
	public int HashStreamReadByte()
	{
		_hashInner.Position = 0;
		_hashStream.Reset();
		return ReadBytes(_hashStream);
	}

	[Benchmark(OperationsPerInvoke = ByteCount)]
	[BenchmarkCategory("ReadByte")]
	public int DataUnitStreamReadByte()
	{
		_dataUnitStream.Position = 0;
		return ReadBytes(_dataUnitStream);
	}

	[Benchmark(Baseline = true, OperationsPerInvoke = ByteCount)]
	[BenchmarkCategory("WriteByte")]
	public void MemoryStreamWriteByte()
	{
		_memoryStream.Position = 0;
		WriteBytes(_memoryStream);
	}

	[Benchmark(OperationsPerInvoke = ByteCount)]
	[BenchmarkCategory("WriteByte")]
	public void HashStreamWriteByte()
	{
		_hashInner.Position = 0;
		_hashStream.Reset();
		WriteBytes(_hashStream);
	}

	[Benchmark(OperationsPerInvoke = ByteCount)]
	[BenchmarkCategory("WriteByte")]
	public void DataUnitStreamWriteByte()
	{
		_dataUnitStream.Position = 0;
		WriteBytes(_dataUnitStream);
		_dataUnitStream.Flush();
	}

	private static int ReadBytes(Stream stream)
	{
		int sum = 0;

		for (int i = 0; i < ByteCount; ++i)
		{
			int value = stream.ReadByte();

			if (value < 0)
			{
				throw new EndOfStreamException();
			}

			sum += value;
		}

		return sum;
	}

	private static void WriteBytes(Stream stream)
	{
		for (int i = 0; i < ByteCount; ++i)
		{
			stream.WriteByte((byte)i);
		}
	}
}
