using BenchmarkDotNet.Attributes;
using CryptoBase.Signatures.Rsa;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using System.Security.Cryptography;
using BouncyCastleInteger = Org.BouncyCastle.Math.BigInteger;

namespace CryptoBase.Benchmark.Signatures.Rsa.Arithmetic;

// RSASP1 on an EMSA-PKCS1-v1_5 encoding of a SHA-256 hash: RsaPrivateOperation.Apply, which blinds and checks the result, beside the platform signing the hash with the same padding and a blinded engine on the same encoding.
public class RsaPrivateOperationBenchmark
{
	private static ReadOnlySpan<byte> Sha256DigestInfo => [0x30, 0x31, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20];

	private readonly byte[] _hash = RandomNumberGenerator.GetBytes(32);
	private byte[] _encoded = [];
	private byte[] _output = [];
	private RsaPrivateOperation _cryptoBase = null!;
	private RSA _bcl = null!;
	private RsaBlindedEngine _bouncyCastle = null!;

	[Params(2048, 3072, 4096)]
	public int Bits { get; set; }

	[GlobalSetup]
	public void Setup()
	{
		_bcl = RSA.Create(Bits);
		RSAParameters parameters = _bcl.ExportParameters(true);
		RsaPublicOperation publicKey = RsaPublicOperation.Create(parameters.Modulus, parameters.Exponent);
		_cryptoBase = RsaPrivateOperation.Create(publicKey, parameters.D, parameters.P, parameters.Q, parameters.DP, parameters.DQ, parameters.InverseQ);

		// EM = 0x00 || 0x01 || PS || 0x00 || T (RFC 8017, Sec. 9.2).
		int length = publicKey.ModulusLength;
		_encoded = new byte[length];
		_output = new byte[length];
		_encoded[1] = 1;
		int t = Sha256DigestInfo.Length + _hash.Length;
		_encoded.AsSpan(2, length - t - 3).Fill(0xFF);
		Sha256DigestInfo.CopyTo(_encoded.AsSpan(length - t));
		_hash.CopyTo(_encoded.AsSpan(length - _hash.Length));

		RsaPrivateCrtKeyParameters key = new(Integer(parameters.Modulus), Integer(parameters.Exponent), Integer(parameters.D), Integer(parameters.P), Integer(parameters.Q), Integer(parameters.DP), Integer(parameters.DQ), Integer(parameters.InverseQ));
		_bouncyCastle = new RsaBlindedEngine();
		_bouncyCastle.Init(true, new ParametersWithRandom(key, new SecureRandom()));

		byte[] bclSignature = _bcl.SignHash(_hash, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
		byte[] bouncyCastleSignature = _bouncyCastle.ProcessBlock(_encoded, 0, _encoded.Length);
		_cryptoBase.Apply(_encoded, _output);

		if (!bclSignature.AsSpan().SequenceEqual(_output) || !bouncyCastleSignature.AsSpan().SequenceEqual(_output.AsSpan(_output.Length - bouncyCastleSignature.Length)))
		{
			throw new InvalidOperationException("The signatures differ.");
		}
	}

	[GlobalCleanup]
	public void Cleanup()
	{
		_cryptoBase.Dispose();
		_bcl.Dispose();
	}

	[Benchmark(Baseline = true)]
	public void CryptoBase()
	{
		_cryptoBase.Apply(_encoded, _output);
	}

	[Benchmark]
	public bool Bcl()
	{
		return _bcl.TrySignHash(_hash, _output, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1, out _);
	}

	[Benchmark]
	public byte[] BouncyCastle()
	{
		return _bouncyCastle.ProcessBlock(_encoded, 0, _encoded.Length);
	}

	private static BouncyCastleInteger Integer(byte[]? value)
	{
		ArgumentNullException.ThrowIfNull(value);

		return new BouncyCastleInteger(1, value);
	}
}
