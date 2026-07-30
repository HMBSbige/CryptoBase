using BenchmarkDotNet.Attributes;
using CryptoBase.SymmetricCryptos.BlockCryptoModes;
using CryptoBase.SymmetricCryptos.BlockCryptos.AES;
using System.Security.Cryptography;

namespace CryptoBase.Benchmark;

[MemoryDiagnoser]
public class XTSBenchmark
{
	[Params(16, 32)]
	public int KeyLength { get; set; }

	[Params(512, 4096)]
	public int ByteLength { get; set; }

	private XtsMode<AesCipher> _xts = null!;
	private byte[] _input = [];
	private byte[] _output = [];
	private byte[] _iv = [];

	[GlobalSetup]
	public void Setup()
	{
		AesCipher dataCipher = AesCipher.Create(RandomNumberGenerator.GetBytes(KeyLength));
		AesCipher tweakCipher = AesCipher.Create(RandomNumberGenerator.GetBytes(KeyLength));

		_xts = new XtsMode<AesCipher>(dataCipher, tweakCipher);
		_input = RandomNumberGenerator.GetBytes(ByteLength);
		_output = new byte[_xts.GetMaxByteCount(ByteLength)];
		_iv = RandomNumberGenerator.GetBytes(_xts.BlockSize);
	}

	[GlobalCleanup]
	public void Cleanup()
	{
		_xts.Dispose();
	}

	[Benchmark(Baseline = true)]
	public void Encrypt()
	{
		_xts.Encrypt(_iv, _input, _output);
	}

	[Benchmark]
	public void Decrypt()
	{
		_xts.Decrypt(_iv, _input, _output);
	}
}
