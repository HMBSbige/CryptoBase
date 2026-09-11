using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Configs;
using CryptoBase.SymmetricCryptos.BlockCryptoModes;
using CryptoBase.SymmetricCryptos.BlockCryptos.Aes;
using System.Security.Cryptography;

namespace CryptoBase.Benchmark.SymmetricCryptos.BlockCryptoModes;

[MemoryDiagnoser]
[CategoriesColumn]
[GroupBenchmarksBy(BenchmarkLogicalGroupRule.ByCategory)]
public class XtsBenchmark
{
	[Params(16, 32)]
	public int KeyLength { get; set; }

	[Params(16, 17, 128, 256, 512, 4096)]
	public int ByteLength { get; set; }

	private XtsMode<AesCipher> _xts = null!;
	private byte[] _input = [];
	private byte[] _output = [];
	private byte[] _ciphertext = [];
	private byte[] _iv = [];

	[GlobalSetup]
	public void Setup()
	{
		AesCipher dataCipher = AesCipher.Create(RandomNumberGenerator.GetBytes(KeyLength));
		AesCipher tweakCipher = AesCipher.Create(RandomNumberGenerator.GetBytes(KeyLength));

		_xts = new XtsMode<AesCipher>(dataCipher, tweakCipher);
		_input = RandomNumberGenerator.GetBytes(ByteLength);
		_output = new byte[_xts.GetMaxByteCount(ByteLength)];
		_ciphertext = new byte[_output.Length];
		_iv = RandomNumberGenerator.GetBytes(_xts.BlockSize);
		_xts.Encrypt(_iv, _input, _ciphertext);
	}

	[GlobalCleanup]
	public void Cleanup()
	{
		_xts.Dispose();
	}

	[Benchmark]
	[BenchmarkCategory("Encrypt")]
	public void Encrypt()
	{
		_xts.Encrypt(_iv, _input, _output);
	}

	[Benchmark]
	[BenchmarkCategory("Decrypt")]
	public void Decrypt()
	{
		_xts.Decrypt(_iv, _ciphertext, _output);
	}
}
