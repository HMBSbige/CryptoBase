using BenchmarkDotNet.Attributes;
using CryptoBase.DataFormatExtensions;
using System.Buffers;
using System.Security.Cryptography;

namespace CryptoBase.Benchmark.DataFormatExtensions;

[MemoryDiagnoser]
public class Base32Benchmark
{
	[Params(1, 4, 5, 6, 1024, 8192)]
	public int ByteLength { get; set; }

	private byte[] _data = [];
	private char[] _encodedChars = [];
	private byte[] _encodedUtf8 = [];
	private byte[] _decoded = [];
	private readonly Base32Encoding _encoding = Base32Encoding.Rfc4648;

	[GlobalSetup]
	public void Setup()
	{
		_data = RandomNumberGenerator.GetBytes(ByteLength);
		_encodedChars = new char[_encoding.GetEncodedLength(ByteLength)];
		_encodedUtf8 = new byte[_encodedChars.Length];
		_decoded = new byte[Base32Encoding.GetMaxDecodedLength(_encodedChars.Length)];
		OperationStatus charStatus = _encoding.EncodeToChars(_data, _encodedChars, out int charConsumed, out int charsWritten);
		OperationStatus utf8Status = _encoding.EncodeToUtf8(_data, _encodedUtf8, out int utf8Consumed, out int bytesWritten);
		if (charStatus is not OperationStatus.Done || utf8Status is not OperationStatus.Done
			|| charConsumed != _data.Length || utf8Consumed != _data.Length
			|| charsWritten != _encodedChars.Length || bytesWritten != _encodedUtf8.Length)
		{
			throw new InvalidOperationException("Failed to initialize Base32 decode inputs.");
		}
	}

	[Benchmark]
	public OperationStatus EncodeToChars()
	{
		return _encoding.EncodeToChars(_data, _encodedChars, out _, out _);
	}

	[Benchmark]
	public OperationStatus EncodeToUtf8()
	{
		return _encoding.EncodeToUtf8(_data, _encodedUtf8, out _, out _);
	}

	[Benchmark]
	public OperationStatus DecodeFromChars()
	{
		return _encoding.DecodeFromChars(_encodedChars, _decoded, out _, out _);
	}

	[Benchmark]
	public OperationStatus DecodeFromUtf8()
	{
		return _encoding.DecodeFromUtf8(_encodedUtf8, _decoded, out _, out _);
	}
}
