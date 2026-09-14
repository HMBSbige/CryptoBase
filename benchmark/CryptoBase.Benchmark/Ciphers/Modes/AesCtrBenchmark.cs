using BenchmarkDotNet.Attributes;
using CryptoBase.Ciphers.Blocks.Aes;
using CryptoBase.Ciphers.Modes;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
using System.Security.Cryptography;

namespace CryptoBase.Benchmark.Ciphers.Modes;

[MemoryDiagnoser]
public class AesCtrBenchmark : BlockModeStreamCipherBenchmarkBase
{
	private CtrMode128<AesCipher> _cryptoBase = null!;
	private SicBlockCipher _bouncyCastle = null!;

	protected override void SetupCryptos()
	{
		byte[] key = RandomNumberGenerator.GetBytes(16);
		byte[] iv = RandomNumberGenerator.GetBytes(16);
		_cryptoBase = Register(CtrMode128<AesCipher>.Create(key, iv));
		_bouncyCastle = new SicBlockCipher(AesUtilities.CreateEngine());
		_bouncyCastle.Init(true, new ParametersWithIV(new KeyParameter(key), iv));
	}

	[Benchmark(Baseline = true)]
	public void CryptoBase()
	{
		Run(_cryptoBase);
	}

	[Benchmark]
	public void BouncyCastle()
	{
		for (int offset = 0; offset < Input.Length; offset += 16)
		{
			_bouncyCastle.ProcessBlock(Input.Slice(offset, 16), Output.Slice(offset, 16));
		}
	}
}
