using BenchmarkDotNet.Attributes;
using CryptoBase.DataFormatExtensions;
using System.Security.Cryptography;

namespace CryptoBase.Benchmark;

[MemoryDiagnoser]
public class Base32Benchmark
{
	[Params(16, 1024)]
	public int ByteLength { get; set; }

	private byte[] _data = [];
	private string _encoded = string.Empty;

	[GlobalSetup]
	public void Setup()
	{
		_data = RandomNumberGenerator.GetBytes(ByteLength);

		ReadOnlySpan<byte> span = _data;
		_encoded = span.ToBase32String();
	}

	[Benchmark]
	public string ToBase32String()
	{
		ReadOnlySpan<byte> span = _data;
		return span.ToBase32String();
	}

	[Benchmark]
	public byte[] FromBase32String()
	{
		return _encoded.AsSpan().FromBase32String();
	}
}
