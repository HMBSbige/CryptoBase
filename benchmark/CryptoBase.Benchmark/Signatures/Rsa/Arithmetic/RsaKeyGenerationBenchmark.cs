using BenchmarkDotNet.Attributes;
using CryptoBase.Signatures.Rsa;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using System.Security.Cryptography;
using BouncyCastleInteger = Org.BouncyCastle.Math.BigInteger;

namespace CryptoBase.Benchmark.Signatures.Rsa.Arithmetic;

// Key generation with e = 65537. The time of one key varies with the candidates it tries, so a run needs many keys. Exporting the key forces the platform to generate it, which it defers to the first use.
public class RsaKeyGenerationBenchmark
{
	private RsaKeyPairGenerator _bouncyCastle = null!;

	[Params(2048, 3072)]
	public int Bits { get; set; }

	[GlobalSetup]
	public void Setup()
	{
		_bouncyCastle = new RsaKeyPairGenerator();
		_bouncyCastle.Init(new RsaKeyGenerationParameters(BouncyCastleInteger.ValueOf(65537), new SecureRandom(), Bits, 100));
	}

	[Benchmark(Baseline = true)]
	public void CryptoBase()
	{
		using RsaPrivateOperation key = RsaPrivateOperation.Generate(Bits, 65537);
	}

	[Benchmark]
	public RSAParameters Bcl()
	{
		using RSA key = RSA.Create(Bits);
		return key.ExportParameters(false);
	}

	[Benchmark]
	public AsymmetricCipherKeyPair BouncyCastle()
	{
		return _bouncyCastle.GenerateKeyPair();
	}
}
