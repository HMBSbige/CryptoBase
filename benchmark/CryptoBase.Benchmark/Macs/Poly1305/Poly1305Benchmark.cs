using BenchmarkDotNet.Attributes;
using CryptoBase.Macs.Poly1305;
using System.Security.Cryptography;
using BouncyCastleKeyParameter = Org.BouncyCastle.Crypto.Parameters.KeyParameter;
using BouncyCastlePoly1305 = Org.BouncyCastle.Crypto.Macs.Poly1305;

namespace CryptoBase.Benchmark.Macs.Poly1305;

[MemoryDiagnoser]
[DisassemblyDiagnoser(3)]
public class Poly1305Benchmark
{
	[Params(0, 16, 64, 128, 256, 1024, 8192)]
	public int ByteLength { get; set; }

	private byte[] _key = [];
	private byte[] _input = [];
	private byte[] _mac = [];

	[GlobalSetup]
	public void Setup()
	{
		_key = RandomNumberGenerator.GetBytes(Poly1305Algorithm.KeyLengthInBytes);
		_input = RandomNumberGenerator.GetBytes(ByteLength);
		_mac = new byte[Poly1305Algorithm.MacLength];
	}

	[Benchmark(Baseline = true)]
	public int CryptoBase()
	{
		return Poly1305Algorithm.Mac(_key, _input, _mac);
	}

	[Benchmark]
	public int BouncyCastle()
	{
		BouncyCastlePoly1305 poly1305 = new();
		poly1305.Init(new BouncyCastleKeyParameter(_key));
		poly1305.BlockUpdate(_input);
		return poly1305.DoFinal(_mac);
	}
}
