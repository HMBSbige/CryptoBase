using CryptoBase.Abstractions.Signatures;
using CryptoBase.Signatures.Rsa;
using System.Diagnostics.CodeAnalysis;
using System.Formats.Asn1;
using System.Numerics;
using System.Security.Cryptography;
using static CryptoBase.Tests.Signatures.Rsa.RsaTestUtils;
using static CryptoBase.Tests.Signatures.SignatureTestUtils;
using static CryptoBase.Tests.TestUtils;

namespace CryptoBase.Tests.Signatures.Rsa;

internal class RsaKeyTest
{
	// The shortest modulus, in bits, that each algorithm fits (RFC 8017): EMSA-PKCS1-v1_5 needs k ≥ tLen + 11 bytes, where the DigestInfo T has 19 bytes before the hash (Sec. 9.2, step 3), and EMSA-PSS
	// with a salt as long as the hash needs emLen = ⌈(modBits − 1)/8⌉ ≥ 2·hLen + 2 bytes (Sec. 9.1.1, step 3).
	private static readonly Dictionary<SignatureAlgorithm, int> MinModulusBits = new()
	{
		[SignatureAlgorithm.RsaPkcs1Sha256] = 489,
		[SignatureAlgorithm.RsaPkcs1Sha384] = 617,
		[SignatureAlgorithm.RsaPkcs1Sha512] = 745,
		[SignatureAlgorithm.RsaPssSha256] = 522,
		[SignatureAlgorithm.RsaPssSha384] = 778,
		[SignatureAlgorithm.RsaPssSha512] = 1034,
	};

	// FIPS 186-5: p and q of nlen/2 bits, each at least √2·2^(nlen/2 − 1), more than 2^(nlen/2 − 100) apart, and probably prime, with gcd(p − 1, e) = gcd(q − 1, e) = 1 (Appendix A.1.3); and
	// 2^(nlen/2) < d < LCM(p − 1, q − 1) with e·d ≡ 1 modulo the LCM (Appendix A.1.1, criterion 3). The values of the Chinese remainder theorem follow from them (RFC 8017, Sec. 3.2).
	[Test]
	[Arguments(65537UL)]
	[Arguments(8589934591UL)]
	public async Task GeneratedKeysMeetFips186(ulong publicExponent)
	{
		using RsaKey key = RsaKey.GenerateKey(2048, publicExponent);
		AsnReader reader = new AsnReader(ExportRsaPrivateKey(key), AsnEncodingRules.DER).ReadSequence();
		BigInteger version = reader.ReadInteger();
		(BigInteger n, BigInteger e, BigInteger d) = (reader.ReadInteger(), reader.ReadInteger(), reader.ReadInteger());
		(BigInteger p, BigInteger q) = (reader.ReadInteger(), reader.ReadInteger());
		(BigInteger dP, BigInteger dQ, BigInteger qInv) = (reader.ReadInteger(), reader.ReadInteger(), reader.ReadInteger());
		BigInteger lcm = (p - 1) * (q - 1) / BigInteger.GreatestCommonDivisor(p - 1, q - 1);
		BigInteger lowerBound = BigInteger.One << 2047;
		byte[] message = CreateDeterministicSource(50);
		using RSA bcl = RSA.Create();
		bcl.ImportRSAPublicKey(ExportRsaPublicKey(key), out _);

		using (Assert.Multiple())
		{
			await Assert.That(reader.HasData).IsFalse();
			await Assert.That(version).IsEqualTo(BigInteger.Zero);
			await Assert.That(key.ModulusBits).IsEqualTo(2048);
			await Assert.That(e).IsEqualTo(new BigInteger(publicExponent));
			await Assert.That(n).IsEqualTo(p * q);
			await Assert.That(n.GetBitLength()).IsEqualTo(2048);
			await Assert.That((p.GetBitLength(), q.GetBitLength())).IsEqualTo((1024L, 1024L));
			await Assert.That(p * p > lowerBound && q * q > lowerBound).IsTrue();
			await Assert.That(BigInteger.Abs(p - q) > BigInteger.One << 924).IsTrue();
			await Assert.That(BigInteger.GreatestCommonDivisor(p - 1, e).IsOne && BigInteger.GreatestCommonDivisor(q - 1, e).IsOne).IsTrue();
			await Assert.That(IsProbablePrime(p) && IsProbablePrime(q)).IsTrue();
			await Assert.That(d > BigInteger.One << 1024 && d < lcm).IsTrue();
			await Assert.That(e * d % lcm).IsEqualTo(BigInteger.One);
			await Assert.That((dP, dQ, qInv * q % p)).IsEqualTo((d % (p - 1), d % (q - 1), BigInteger.One));
			await Assert.That(Algorithms.Where(key.Supports)).IsEquivalentTo(Algorithms, CollectionOrdering.Matching);

			foreach (SignatureAlgorithm algorithm in Algorithms)
			{
				(HashAlgorithmName hash, RSASignaturePadding padding, _) = ParametersOf(algorithm);
				await Assert.That(bcl.VerifyData(message, Sign(key, algorithm, message), hash, padding)).IsTrue().Because(algorithm.ToString());
			}
		}
	}

	[Test]
	[Arguments(0)]
	[Arguments(-2048)]
	[Arguments(1024)]
	[Arguments(2040)]
	[Arguments(2047)]
	[Arguments(2049)]
	[Arguments(2052)]
	[Arguments(16392)]
	[Arguments(int.MaxValue)]
	[Arguments(int.MinValue)]
	public async Task GenerateKeyRejectsOtherModulusSizes(int modulusBits)
	{
		await Assert.That(() => RsaKey.GenerateKey(modulusBits)).ThrowsExactly<ArgumentOutOfRangeException>().WithParameterName("modulusBits");
	}

	[Test]
	[Arguments(0UL)]
	[Arguments(1UL)]
	[Arguments(3UL)]
	[Arguments(65535UL)]
	[Arguments(65536UL)]
	[Arguments(65538UL)]
	[Arguments(8589934592UL)]
	[Arguments(8589934593UL)]
	[Arguments(ulong.MaxValue)]
	public async Task GenerateKeyRejectsOtherPublicExponents(ulong publicExponent)
	{
		await Assert.That(() => RsaKey.GenerateKey(2048, publicExponent)).ThrowsExactly<ArgumentException>().WithParameterName("publicExponent");
	}

	[Test]
	[Arguments(512)]
	[Arguments(521)]
	[Arguments(522)]
	[Arguments(616)]
	[Arguments(617)]
	[Arguments(744)]
	[Arguments(745)]
	[Arguments(777)]
	[Arguments(778)]
	[Arguments(1033)]
	[Arguments(1034)]
	[Arguments(2048)]
	[Arguments(16384)]
	[SuppressMessage("ReSharper", "AccessToDisposedClosure", Justification = "Assertions finish before disposal.")]
	public async Task SupportsTheAlgorithmsThatFitTheModulus(int bits)
	{
		using RsaKey key = RsaKey.ImportRsaPublicKey(RsaPublicKey(Modulus(bits), 65537));
		byte[] message = CreateDeterministicSource(10);
		byte[] signature = new byte[(bits + 7) / 8];

		using (Assert.Multiple())
		{
			await Assert.That(key.ModulusBits).IsEqualTo(bits);

			foreach (SignatureAlgorithm algorithm in Algorithms)
			{
				if (bits >= MinModulusBits[algorithm])
				{
					await Assert.That(key.Supports(algorithm)).IsTrue().Because(algorithm.ToString());
					await Assert.That(key.GetMaxSignatureLength(algorithm)).IsEqualTo(signature.Length).Because(algorithm.ToString());
					await Assert.That(key.Verify(algorithm, message, signature)).IsFalse().Because(algorithm.ToString());
					continue;
				}

				await Assert.That(key.Supports(algorithm)).IsFalse().Because(algorithm.ToString());
				await Assert.That(() => key.GetMaxSignatureLength(algorithm)).Throws<ArgumentException>().WithParameterName("algorithm");
				await Assert.That(() => key.Verify(algorithm, message, signature)).Throws<ArgumentException>().WithParameterName("algorithm");
			}
		}
	}

	public static IEnumerable<Func<(string Case, RSAParameters Key)>> SigningKeys()
	{
		yield return static () => ("512 bits", PrivateParameters(512));
		yield return static () => ("1025 bits, emLen = k − 1", PssExamples[1].Key);
		yield return static () => ("1026 bits, 7 unused bits in EM", PssExamples[2].Key);
		yield return static () => ("1031 bits, 1 unused bit in EM", PssExamples[7].Key);
		yield return static () => ("2048 bits", PrivateParameters());
	}

	// Each signature equals RSASP1 without the Chinese remainder theorem of the reference encoding: for RSASSA-PKCS1-v1_5 with the NULL parameters, and for RSASSA-PSS with the salt given.
	[Test]
	[MethodDataSource(nameof(SigningKeys))]
	public async Task SignaturesMatchTheReferenceEncodings(string @case, RSAParameters parameters)
	{
		using RsaKey key = RsaKey.ImportRsaPrivateKey(RsaPrivateKey(parameters));
		int bits = ModulusBits(parameters);
		int length = (bits + 7) / 8;
		byte[] message = CreateDeterministicSource(77);

		using (Assert.Multiple())
		{
			await Assert.That(Algorithms.Where(key.Supports)).IsEquivalentTo(Algorithms.Where(algorithm => bits >= MinModulusBits[algorithm]), CollectionOrdering.Matching).Because(@case);

			foreach (SignatureAlgorithm algorithm in Algorithms.Where(key.Supports))
			{
				(HashAlgorithmName hash, RSASignaturePadding padding, int hashLength) = ParametersOf(algorithm);
				byte[] mHash = CryptographicOperations.HashData(hash, message);
				byte[] salt = padding == RSASignaturePadding.Pss ? CreateDeterministicSource(hashLength) : [];
				byte[] encodedMessage = padding == RSASignaturePadding.Pss ? EncodePss(bits, hash, mHash, salt) : EncodePkcs1(length, DigestInfo(hash, mHash));
				byte[] expected = RawSign(parameters, encodedMessage);
				byte[] signature = CreateGuardedBuffer(0, length);
				int written = key.Sign(algorithm, message, salt, signature);

				await AssertOutput(signature, expected, written);
				await Assert.That(key.Verify(algorithm, message, expected)).IsTrue().Because($"{@case}, {algorithm}");

				if (padding == RSASignaturePadding.Pss)
				{
					await Assert.That(Sign(key, algorithm, message)).IsNotEquivalentTo(expected).Because($"{@case}, {algorithm}");
				}
				else
				{
					await Assert.That(Sign(key, algorithm, message)).IsEquivalentTo(expected, CollectionOrdering.Matching).Because($"{@case}, {algorithm}");
				}
			}
		}
	}

	// RFC 8017, Sec. 9.1.2, for keys whose EM fills its bytes but for one bit (2048), whose EM is a byte shorter than the modulus (1025), and whose EM leaves 7 bits unused (1026).
	[Test]
	[Arguments(2048)]
	[Arguments(1025)]
	[Arguments(1026)]
	public async Task PssVerificationFollowsRfc8017(int bits)
	{
		RSAParameters parameters = KeyOf(bits);
		BigInteger modulus = Os2Ip(parameters.Modulus);
		int length = parameters.Modulus!.Length;
		using RsaKey key = RsaKey.ImportRsaPublicKey(RsaPublicKey(modulus, Os2Ip(parameters.Exponent)));
		byte[] message = "message"u8.ToArray();
		byte[] mHash = SHA256.HashData(message);
		int zeroBits = 8 * ((bits + 6) / 8) - (bits - 1);
		List<(string Case, byte[] EncodedMessage)> invalid =
		[
			("salt of 0 bytes", EncodePss(bits, HashAlgorithmName.SHA256, mHash, [])),
			("salt of 20 bytes", EncodePss(bits, HashAlgorithmName.SHA256, mHash, RandomNumberGenerator.GetBytes(20))),
			("salt of 33 bytes", EncodePss(bits, HashAlgorithmName.SHA256, mHash, RandomNumberGenerator.GetBytes(33))),
			("trailer field 0xCC", EncodePss(bits, HashAlgorithmName.SHA256, mHash, RandomNumberGenerator.GetBytes(32), trailer: 0xCC)),
			("MGF1 with SHA-1", EncodePss(bits, HashAlgorithmName.SHA256, mHash, RandomNumberGenerator.GetBytes(32), maskHash: HashAlgorithmName.SHA1)),
			("0x02 after the padding", EncodePss(bits, HashAlgorithmName.SHA256, mHash, RandomNumberGenerator.GetBytes(32), changeDb: static db => db[^33] = 0x02)),
			("nonzero padding", EncodePss(bits, HashAlgorithmName.SHA256, mHash, RandomNumberGenerator.GetBytes(32), changeDb: static db => db[1] = 0x01)),
			("another message", EncodePss(bits, HashAlgorithmName.SHA256, SHA256.HashData("massage"u8), RandomNumberGenerator.GetBytes(32))),
			("SHA-384", EncodePss(bits, HashAlgorithmName.SHA384, SHA384.HashData(message), RandomNumberGenerator.GetBytes(32))),
			("RSASSA-PKCS1-v1_5", EncodePkcs1((bits + 6) / 8, DigestInfo(HashAlgorithmName.SHA256, mHash))),
		];

		if (zeroBits > 0)
		{
			// The lowest of the bits that must be zero (step 6), in an EM below the modulus, so that a signature gives it.
			byte topBit = (byte)(0x80 >> zeroBits - 1);
			byte[] encodedMessage;

			do
			{
				encodedMessage = EncodePss(bits, HashAlgorithmName.SHA256, mHash, RandomNumberGenerator.GetBytes(32), topBits: topBit);
			}
			while (Os2Ip(encodedMessage) >= modulus);

			invalid.Add(("a bit beyond emBits", encodedMessage));
		}

		byte[] valid = RawSign(parameters, EncodePss(bits, HashAlgorithmName.SHA256, mHash, RandomNumberGenerator.GetBytes(32)));

		using (Assert.Multiple())
		{
			await Assert.That(key.Verify(SignatureAlgorithm.RsaPssSha256, message, valid)).IsTrue();

			foreach ((string @case, byte[] encodedMessage) in invalid)
			{
				await Assert.That(key.Verify(SignatureAlgorithm.RsaPssSha256, message, RawSign(parameters, encodedMessage))).IsFalse().Because(@case);
			}

			// A message representative of k bytes does not fit an EM one byte shorter (RFC 8017, Sec. 8.1.2, step 2c), and one at or above the modulus is out of range (step 2b).
			if (bits is 1025)
			{
				await Assert.That(key.Verify(SignatureAlgorithm.RsaPssSha256, message, I2Osp(modulus - 1, length))).IsFalse();
			}

			foreach (byte[] signature in (byte[][])[I2Osp(modulus, length), I2Osp(modulus + 1, length), Enumerable.Repeat((byte)0xFF, length).ToArray(), new byte[length], valid.AsSpan(1).ToArray(), [0x00, .. valid], []])
			{
				await Assert.That(key.Verify(SignatureAlgorithm.RsaPssSha256, message, signature)).IsFalse().Because(Convert.ToHexString(signature.AsSpan(0, Math.Min(4, signature.Length))));
			}
		}
	}

	// RFC 8017, Sec. 8.2.2: the encoded message must equal EMSA-PKCS1-V1_5-ENCODE of the message, whose DigestInfo has NULL or absent parameters (RFC 5246, Sec. 4.7).
	[Test]
	[Arguments(2048)]
	[Arguments(1025)]
	public async Task Pkcs1VerificationComparesTheWholeEncoding(int bits)
	{
		RSAParameters parameters = KeyOf(bits);
		BigInteger modulus = Os2Ip(parameters.Modulus);
		int length = parameters.Modulus!.Length;
		using RsaKey key = RsaKey.ImportRsaPublicKey(RsaPublicKey(modulus, Os2Ip(parameters.Exponent)));
		byte[] message = "message"u8.ToArray();
		byte[] digest = SHA256.HashData(message);
		byte[] digestInfo = DigestInfo(HashAlgorithmName.SHA256, digest);
		byte[] withoutNull = DigestInfo(HashAlgorithmName.SHA256, digest, nullParameters: false);
		byte[] valid = EncodePkcs1(length, digestInfo);
		(string Case, byte[] EncodedMessage)[] invalid =
		[
			("DigestInfo without parameters, with a long-form length", EncodePkcs1(length, X509.X509TestUtils.WithRedundantLengthByte(withoutNull))),
			("DigestInfo with a long-form length", EncodePkcs1(length, X509.X509TestUtils.WithRedundantLengthByte(digestInfo))),
			("DigestInfo of SHA-384", EncodePkcs1(length, DigestInfo(HashAlgorithmName.SHA384, SHA384.HashData(message)))),
			("DigestInfo of SHA-256 with a hash of SHA-384's length", EncodePkcs1(length, Sequence(Sequence(Oid(HashOid(HashAlgorithmName.SHA256)), [0x05, 0x00]), Tlv(0x04, SHA384.HashData(message))))),
			("hash of another message", EncodePkcs1(length, DigestInfo(HashAlgorithmName.SHA256, SHA256.HashData("massage"u8)))),
			("block type 2", [.. valid.AsSpan(0, 1), 0x02, .. valid.AsSpan(2)]),
			("0xFE in the padding", [.. valid.AsSpan(0, 5), 0xFE, .. valid.AsSpan(6)]),
			("no separator", [.. valid.AsSpan(0, length - digestInfo.Length - 1), 0xFF, .. digestInfo]),
			("padding cut short by a garbage byte", [0x00, 0x01, .. Enumerable.Repeat((byte)0xFF, length - digestInfo.Length - 5), 0x00, 0x00, 0x00, .. digestInfo]),
			("no leading zero byte", [.. valid.AsSpan(1), 0x00]),
			("RSASSA-PSS", EncodePss(bits, HashAlgorithmName.SHA256, digest, RandomNumberGenerator.GetBytes(32))),
		];

		using (Assert.Multiple())
		{
			await Assert.That(key.Verify(SignatureAlgorithm.RsaPkcs1Sha256, message, RawSign(parameters, valid))).IsTrue();
			await Assert.That(key.Verify(SignatureAlgorithm.RsaPkcs1Sha256, message, RawSign(parameters, EncodePkcs1(length, withoutNull)))).IsTrue();
			await Assert.That(key.Verify(SignatureAlgorithm.RsaPkcs1Sha384, message, RawSign(parameters, valid))).IsFalse();

			foreach ((string @case, byte[] encodedMessage) in invalid)
			{
				// An encoding at or above the modulus has no signature.
				if (Os2Ip(encodedMessage) < modulus)
				{
					await Assert.That(key.Verify(SignatureAlgorithm.RsaPkcs1Sha256, message, RawSign(parameters, encodedMessage))).IsFalse().Because(@case);
				}
			}
		}
	}

	[Test]
	public async Task SignaturesVerifyWithTheBcl()
	{
		using RsaKey key = ImportKey();
		using RSA bcl = CreateBclKey();
		byte[] message = CreateDeterministicSource(1000);

		using (Assert.Multiple())
		{
			foreach (SignatureAlgorithm algorithm in Algorithms)
			{
				(HashAlgorithmName hash, RSASignaturePadding padding, _) = ParametersOf(algorithm);
				await Assert.That(bcl.VerifyData(message, Sign(key, algorithm, message), hash, padding)).IsTrue().Because(algorithm.ToString());
				await Assert.That(key.Verify(algorithm, message, bcl.SignData(message, hash, padding))).IsTrue().Because(algorithm.ToString());
			}
		}
	}

	// The internal entry for known-answer tests checks the salt as Sign checks the destination, before anything is written.
	[Test]
	[SuppressMessage("ReSharper", "AccessToDisposedClosure", Justification = "Assertions finish before disposal.")]
	public async Task GivenSaltsMustFit()
	{
		using RsaKey key = ImportKey();
		byte[] destination = CreateGuardedBuffer(0, key.GetMaxSignatureLength(SignatureAlgorithm.RsaPssSha256));
		byte[] message = CreateDeterministicSource(10);

		using (Assert.Multiple())
		{
			await Assert.That(() => key.Sign(SignatureAlgorithm.RsaPssSha256, message, new byte[31], destination)).Throws<ArgumentException>().WithParameterName("salt");
			await Assert.That(() => key.Sign(SignatureAlgorithm.RsaPssSha256, message, new byte[33], destination)).Throws<ArgumentException>().WithParameterName("salt");
			await Assert.That(() => key.Sign(SignatureAlgorithm.RsaPkcs1Sha256, message, new byte[1], destination)).Throws<ArgumentException>().WithParameterName("salt");
			await Assert.That(destination).All(static value => value is DestinationSentinel);
		}
	}

	[Test]
	[SuppressMessage("ReSharper", "AccessToDisposedClosure", Justification = "Parallel.For returns before disposal.")]
	public async Task SignsAndVerifiesConcurrently()
	{
		using RsaKey key = ImportKey();
		byte[] message = CreateDeterministicSource(64);
		int failures = 0;

		Parallel.For(0, 4 * Algorithms.Length * Math.Max(4, Environment.ProcessorCount / 4), i =>
		{
			SignatureAlgorithm algorithm = Algorithms[i % Algorithms.Length];
			byte[] signature = Sign(key, algorithm, message);

			if (!key.Verify(algorithm, message, signature) || key.Verify(algorithm, Flip(message, i % message.Length), signature))
			{
				Interlocked.Increment(ref failures);
			}
		});

		await Assert.That(failures).IsEqualTo(0);
	}

	[Test]
	public async Task DisposedInstancesThrow()
	{
		RsaKey key = ImportKey();
		byte[] destination = new byte[key.RsaPrivateKeyLength];
		key.Dispose();
		key.Dispose();

		using (Assert.Multiple())
		{
			await Assert.That(() => key.ModulusBits).ThrowsExactly<ObjectDisposedException>();
			await Assert.That(() => key.RsaPublicKeyLength).ThrowsExactly<ObjectDisposedException>();
			await Assert.That(() => key.RsaPrivateKeyLength).ThrowsExactly<ObjectDisposedException>();
			await Assert.That(() => key.ExportRsaPublicKey(destination)).ThrowsExactly<ObjectDisposedException>();
			await Assert.That(() => key.ExportRsaPrivateKey(destination)).ThrowsExactly<ObjectDisposedException>();
			await Assert.That(() => key.Sign(SignatureAlgorithm.RsaPssSha256, [], new byte[32], destination)).ThrowsExactly<ObjectDisposedException>();
		}
	}

	private static RSAParameters KeyOf(int bits)
	{
		return bits switch
		{
			1025 => PssExamples[1].Key,
			1026 => PssExamples[2].Key,
			_ => PrivateParameters(bits)
		};
	}

	// Miller-Rabin with the first 32 primes as bases.
	private static bool IsProbablePrime(BigInteger n)
	{
		BigInteger d = n - 1;
		int s = 0;

		while (d.IsEven)
		{
			d >>= 1;
			++s;
		}

		int[] bases = [.. Enumerable.Range(2, 130).Where(static i => Enumerable.Range(2, i - 2).All(j => i % j is not 0)).Take(32)];

		foreach (int a in bases)
		{
			BigInteger x = BigInteger.ModPow(a, d, n);

			if (x.IsOne || x == n - 1)
			{
				continue;
			}

			bool composite = true;

			for (int i = 1; i < s && composite; ++i)
			{
				x = BigInteger.ModPow(x, 2, n);
				composite = x != n - 1;
			}

			if (composite)
			{
				return false;
			}
		}

		return true;
	}
}
