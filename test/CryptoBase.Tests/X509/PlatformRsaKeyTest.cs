using CryptoBase.Abstractions.Signatures;
using CryptoBase.Tests.Wycheproof;
using CryptoBase.X509;
using System.Diagnostics.CodeAnalysis;
using System.Formats.Asn1;
using System.Numerics;
using System.Reflection;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using static CryptoBase.Tests.Signatures.SignatureTestUtils;
using static CryptoBase.Tests.TestUtils;
using static CryptoBase.Tests.X509.X509TestUtils;
using RsaKey = CryptoBase.Signatures.Rsa.RsaKey;

namespace CryptoBase.Tests.X509;

[SuppressMessage("ReSharper", "AccessToDisposedClosure")]
public class PlatformRsaKeyTest
{
	private static readonly byte[] RsaEncryption = Sequence(Oid("1.2.840.113549.1.1.1"), [0x05, 0x00]);

	// RSAPrivateKey (RFC 8017, Appendix A.1.2) of 1025 bits, so that emLen = k − 1 for RSASSA-PSS, and of 1026 bits, so that emBits leaves 7 bits of EM unused.
	private static readonly RSAParameters Key1025 = ReadRsaPrivateKey("MIICXAIBAAKBgQHRW6qTT3FttewNs0udSu/tyFTyUR2TslWZBMMOMWbZIT4n0pswTJ0LLuhvrx36G1RIbddTzOyQ19jmuYHxs6b4PMuQPqjiZczew3aPHFHi3Fe8v3sbNrI0tyn6QfqhGQ7fjr0MeYNd00Po9zz4Wh02UUxZEdtRoq8F7dt0xgWcawIDAQABAoGAFUQ+KFtCEMR2lC20b+zDyDcWgrhoRJ6qwMJx840YaSXWxFUgmHV329H591imYw6qrGCwrXi4+umSVQD3SkdugtnaYYVkw2JGWjg7gpH12cT/pBFGouiu0R1pXxu+ieCsN9ku/tTTjlZr7ri1wBeYcCNOnzJHn0KKp72VBUZMgmkCQQH3ZSNFM2Kfw5tbJpVNxHpydweHLYvNBRn8rXB9JoFFyY2x7B4sYqpwSN5a4Yy7Kby51Xr9Ja0K+j/sAKX2wvPPAkEA7KgKA0OvjSHAqjzCuGDQBevmSkc4HV6nqJSZDyMi4mRNje9xxz1SM9xCB5bB7AFCZWVjLNRIWahw2mKkIUAIpQJANXXYOREr+Cud5CBE2u1y05Uwh3qezjcse1kwCRp9wBuXoL2itrQDxcj3VE9/0qCsGlBBr4DAz9mj0DyBY6NwoQJAWvRqhL6q5e8nAUbA/+QVj3EO3VVp97+9aElUWkEC00gBlp+EdzLWOSBaMFh8x5vkTNwetcgQ1oSqewSWWEEoEQJBAItH6YuoaYqGxECDZ0Utpj2f7iMjvMo7A5CayliQjidupdm9PlSzJxv/bmoGh0Y1sXq5gUtuN8WWuDUMPWtZIcU=");

	private static readonly RSAParameters Key1026 = ReadRsaPrivateKey("MIICXwIBAAKBgQONBoWcTTQrxwl6Q0VQ1jJFT+LrwEfuPobdakVhdumar9Ir3WeTMf+yks/5FW3Fqy4+DSv/2Ph2NS2r53TniVWHDV2RxngvrrQzt4XGxL3zkYezbqhHVbC29NzPYRtA4TPi8wHIhz5qpVGIfaV1BoT6/HoTnTCde+LXyXxcVkWF4QIDAQABAoGBAyvySWGlLBZ2QCbu83kS+fAjPQNqylUpkHkxNSurdVlv9oCr0JoPrN8qd4168IQBNNrEFSr/+F5Nfa/wm+E8MB+Ew48rd1EwDGsY+pPKcId1cyB7ki4gPV8tmJ9MAShm6edMFERjgb+uQYD22p7r+0jXGbfC9L1pVhdoz0UgThBJAkEB+ThnGWs1bdwKy9vWCrMWgKQQKAkwUlPJfb+s+YlWcLS54/wbUU7mUWizvB419SUoSNoKQipsA3fEUTUkA5q26wJBAcycqTuSchLiK2YAfezQcAqfyrXoj7rZLG1B5ozCBzuCZUlu0w69/UGZFZVIJEQezptMftFIZv1XH0POJKLyG2MCQQDYabG4MLVVVuGFC6k3Mhmchyqoi68YRO3VoMqOpabSZogOQcrN3HdKPghnt6UzWnRUKJomV5enMKF2i8XeiWJ7AkEBloBT4l02C3BK+LRKberuVpH7JlteLXpoeOwF+gdqtpw3o30JCyOlFHVz1NFcIDpIAEqcSTrqmX5/+yk8sAmXHQJBALuvzSDY3CyPtiu6l3vAYDInvhFMQs3GBPwm5x0hU8amc2RXohThj9ZAS+QNeBRFb6aaj5a4ZmXWBJQc38d+hZ4=");

	public enum PssBehavior
	{
		Sign,
		Refuse,
		MaximumSalt
	}

	[Test]
	[MatrixDataSource]
	public async Task SignsThroughThePlatformAndVerifiesLikeTheBcl([Matrix(1024, 2048, 3072)] int bits)
	{
		RSA platform = CreateRsa(bits);
		byte[] subjectPublicKeyInfo = platform.ExportSubjectPublicKeyInfo();
		using RSA bcl = CreateRsa(bits);
		using PlatformRsaKey key = new(platform);
		using PlatformRsaKey publicKey = PlatformRsaKey.ImportSubjectPublicKeyInfo(subjectPublicKeyInfo);
		byte[] message = CreateDeterministicSource(100);

		using (Assert.Multiple())
		{
			await Assert.That(key.HasPrivateKey).IsTrue();
			await Assert.That(publicKey.HasPrivateKey).IsFalse();
			await Assert.That(ExportSubjectPublicKeyInfo(key)).IsEquivalentTo(subjectPublicKeyInfo, CollectionOrdering.Matching);
			await Assert.That(ExportSubjectPublicKeyInfo(publicKey)).IsEquivalentTo(subjectPublicKeyInfo, CollectionOrdering.Matching);

			// A 1024-bit modulus is too short for RSASSA-PSS with SHA-512, which needs 1034 bits (RFC 8017, Sec. 9.1.1).
			foreach (SignatureAlgorithm algorithm in (SignatureAlgorithm[])[.. Enum.GetValues<SignatureAlgorithm>(), 0, (SignatureAlgorithm)int.MaxValue])
			{
				bool supported = RsaAlgorithms.Contains(algorithm) && !(bits is 1024 && algorithm is SignatureAlgorithm.RsaPssSha512);
				await Assert.That(key.Supports(algorithm)).IsEqualTo(supported).Because(algorithm.ToString());
				await Assert.That(publicKey.Supports(algorithm)).IsEqualTo(supported).Because(algorithm.ToString());
			}

			foreach (SignatureAlgorithm algorithm in RsaAlgorithms.Where(key.Supports))
			{
				(HashAlgorithmName hash, RSASignaturePadding padding) = RsaParametersOf(algorithm);
				byte[] signatureOutput = CreateGuardedBuffer(1, key.GetMaxSignatureLength(algorithm));
				int written = key.Sign(algorithm, message, signatureOutput.AsSpan(1));
				byte[] signature = signatureOutput.AsSpan(1, written).ToArray();
				byte[] bclSignature = bcl.SignData(message, hash, padding);

				await Assert.That(key.GetMaxSignatureLength(algorithm)).IsEqualTo((bits + 7) / 8);
				await Assert.That(written).IsEqualTo((bits + 7) / 8);
				await AssertOutput(signatureOutput, 1, signature);
				await Assert.That(bcl.VerifyData(message, signature, hash, padding)).IsTrue().Because(algorithm.ToString());
				await Assert.That(key.Verify(algorithm, message, signature)).IsTrue();
				await Assert.That(publicKey.Verify(algorithm, message, signature)).IsTrue();
				await Assert.That(publicKey.Verify(algorithm, message, bclSignature)).IsTrue();
				await Assert.That(publicKey.Verify(algorithm, Flip(message, 0), signature)).IsFalse();
				await Assert.That(publicKey.Verify(algorithm, message, Flip(signature, signature.Length - 1))).IsFalse();
			}
		}
	}

	// The constructor signs once with RSASSA-PSS and SHA-256; a key that refuses RSASSA-PSS, as some smart cards and TPMs do, or makes it with a salt of another length, here the longest, signs once
	// more with RSASSA-PKCS1-v1_5 and supports that alone.
	[Test]
	[Arguments(PssBehavior.Sign, true, 0)]
	[Arguments(PssBehavior.Refuse, false, 1)]
	[Arguments(PssBehavior.MaximumSalt, false, 1)]
	public async Task TheConstructorFindsWhetherTheKeyMakesRsassaPss(PssBehavior pss, bool makesPss, int pkcs1Signatures)
	{
		TestRsa platform = new(RsaPrivateParameters(), pss);
		using PlatformRsaKey key = new(platform);
		(int pssRequests, int pkcs1Requests) = (platform.PssRequests, platform.Pkcs1Requests);
		byte[] message = [1, 2, 3];
		using RSA verifier = CreateRsa();

		using (Assert.Multiple())
		{
			await Assert.That(pssRequests).IsEqualTo(1);
			await Assert.That(pkcs1Requests).IsEqualTo(pkcs1Signatures);

			foreach (SignatureAlgorithm algorithm in RsaAlgorithms)
			{
				bool isPss = algorithm is SignatureAlgorithm.RsaPssSha256 or SignatureAlgorithm.RsaPssSha384 or SignatureAlgorithm.RsaPssSha512;
				await Assert.That(key.Supports(algorithm)).IsEqualTo(makesPss || !isPss).Because(algorithm.ToString());
			}

			byte[] signature = Sign(key, SignatureAlgorithm.RsaPkcs1Sha384, message);
			await Assert.That(verifier.VerifyData(message, signature, HashAlgorithmName.SHA384, RSASignaturePadding.Pkcs1)).IsTrue();

			if (!makesPss)
			{
				await Assert.That(() => key.Sign(SignatureAlgorithm.RsaPssSha256, message, new byte[256])).Throws<ArgumentException>().WithParameterName("algorithm");
			}
		}
	}

	// RSACryptoServiceProvider, a key of CryptoAPI, refuses RSASSA-PSS on Windows.
	[Test]
	public async Task CryptoApiKeysSupportRsassaPkcs1Alone()
	{
		if (!OperatingSystem.IsWindows())
		{
			Skip.Test("CryptoAPI keys are on Windows.");
			return;
		}

		RSACryptoServiceProvider platform = new();
		platform.ImportParameters(RsaPrivateParameters());
		using PlatformRsaKey key = new(platform);

		await Assert.That(RsaAlgorithms.Where(key.Supports)).IsEquivalentTo([SignatureAlgorithm.RsaPkcs1Sha256, SignatureAlgorithm.RsaPkcs1Sha384, SignatureAlgorithm.RsaPkcs1Sha512], CollectionOrdering.Matching);
	}

	[Test]
	public async Task KeysThatFailToSignAreRefused()
	{
		RSA publicOnly = RSA.Create();
		publicOnly.ImportParameters(new RSAParameters { Modulus = RsaPrivateParameters().Modulus, Exponent = RsaPrivateParameters().Exponent });
		TestRsa corrupt = new(RsaPrivateParameters(), corrupt: true);

		using (Assert.Multiple())
		{
			await Assert.That(() => new PlatformRsaKey(publicOnly)).ThrowsExactly<CryptographicException>();
			await Assert.That(() => new PlatformRsaKey(corrupt)).ThrowsExactly<CryptographicException>();

			// The caller still owns the keys.
			await Assert.That(publicOnly.ExportSubjectPublicKeyInfo()).IsNotEmpty();
			await Assert.That(corrupt.IsDisposed).IsFalse();
			await Assert.That(corrupt.PssRequests + corrupt.Pkcs1Requests).IsEqualTo(2);
		}

		publicOnly.Dispose();
		corrupt.Dispose();
	}

	// The caller names the algorithms, and the constructor signs nothing; those that the modulus does not fit are left out.
	[Test]
	public async Task DeclaredAlgorithmsSignNothingUntilSign()
	{
		TestRsa refusing = new(RsaPrivateParameters(), PssBehavior.Refuse);
		using PlatformRsaKey declared = new(refusing, [SignatureAlgorithm.RsaPkcs1Sha256, SignatureAlgorithm.RsaPssSha256, SignatureAlgorithm.RsaPkcs1Sha256]);
		(int pssRequests, int pkcs1Requests) = (refusing.PssRequests, refusing.Pkcs1Requests);
		using PlatformRsaKey shortModulus = new(CreateRsa(1024), [SignatureAlgorithm.RsaPssSha512, SignatureAlgorithm.RsaPssSha384]);
		byte[] destination = CreateGuardedBuffer(0, 256);

		using (Assert.Multiple())
		{
			await Assert.That(pssRequests + pkcs1Requests).IsZero();
			await Assert.That(RsaAlgorithms.Where(declared.Supports)).IsEquivalentTo([SignatureAlgorithm.RsaPkcs1Sha256, SignatureAlgorithm.RsaPssSha256], CollectionOrdering.Matching);
			await Assert.That(RsaAlgorithms.Where(shortModulus.Supports)).IsEquivalentTo([SignatureAlgorithm.RsaPssSha384], CollectionOrdering.Matching);
			await Assert.That(declared.Verify(SignatureAlgorithm.RsaPkcs1Sha256, [1], Sign(declared, SignatureAlgorithm.RsaPkcs1Sha256, [1]))).IsTrue();

			// The key refuses an algorithm that the caller names, so Sign throws as the device fails, and leaves destination alone.
			await Assert.That(() => declared.Sign(SignatureAlgorithm.RsaPssSha256, [1], destination)).ThrowsExactly<CryptographicException>();
			await Assert.That(destination).All(static value => value is DestinationSentinel);
			await Assert.That(() => declared.Sign(SignatureAlgorithm.RsaPkcs1Sha384, [1], destination)).Throws<ArgumentException>().WithParameterName("algorithm");
		}
	}

	[Test]
	public async Task DeclaredAlgorithmsMustBeRsa()
	{
		using (Assert.Multiple())
		{
			foreach (SignatureAlgorithm algorithm in (SignatureAlgorithm[])[SignatureAlgorithm.EcdsaSha256, SignatureAlgorithm.MLDsa44, 0, (SignatureAlgorithm)7000])
			{
				TestRsa platform = new(RsaPrivateParameters());
				await Assert.That(() => new PlatformRsaKey(platform, [SignatureAlgorithm.RsaPkcs1Sha256, algorithm])).Throws<ArgumentException>().WithParameterName("algorithms").Because(algorithm.ToString());
				await Assert.That(platform.IsDisposed).IsFalse();
				platform.Dispose();
			}
		}
	}

	// Each signature is verified before it is returned, so a corrupt one throws and leaves destination alone.
	[Test]
	public async Task SignaturesThatDoNotVerifyThrow()
	{
		using PlatformRsaKey key = new(new TestRsa(RsaPrivateParameters(), corrupt: true), RsaAlgorithms);
		byte[] destination = CreateGuardedBuffer(0, 256);

		using (Assert.Multiple())
		{
			foreach (SignatureAlgorithm algorithm in RsaAlgorithms)
			{
				await Assert.That(() => key.Sign(algorithm, [1, 2, 3], destination)).ThrowsExactly<CryptographicException>().Because(algorithm.ToString());
			}

			await Assert.That(destination).All(static value => value is DestinationSentinel);
		}
	}

	[Test]
	public async Task PublicKeysVerifyButDoNotSign()
	{
		using PlatformRsaKey key = PlatformRsaKey.ImportSubjectPublicKeyInfo(CreateRsa().ExportSubjectPublicKeyInfo());
		byte[] destination = CreateGuardedBuffer(0, 256);

		using (Assert.Multiple())
		{
			await Assert.That(() => key.Sign(SignatureAlgorithm.RsaPkcs1Sha256, [1], destination)).ThrowsExactly<InvalidOperationException>();
			await Assert.That(() => key.Sign(SignatureAlgorithm.EcdsaSha256, [1], destination)).Throws<ArgumentException>().WithParameterName("algorithm");
			await Assert.That(() => key.Pkcs8PrivateKeyLength).ThrowsExactly<InvalidOperationException>();
			await Assert.That(() => key.ExportPkcs8PrivateKey(destination)).ThrowsExactly<InvalidOperationException>();
			await Assert.That(destination).All(static value => value is DestinationSentinel);
		}
	}

	[Test]
	public async Task NeverExportsThePrivateKey()
	{
		using PlatformRsaKey key = new(CreateRsa());
		byte[] destination = CreateGuardedBuffer(0, 2000);

		using (Assert.Multiple())
		{
			await Assert.That(() => key.Pkcs8PrivateKeyLength).ThrowsExactly<InvalidOperationException>();
			await Assert.That(() => key.ExportPkcs8PrivateKey(destination)).ThrowsExactly<InvalidOperationException>();
			await Assert.That(destination).All(static value => value is DestinationSentinel);
		}
	}

	[Test]
	public async Task InvalidArgumentsThrowBeforeWriting()
	{
		using PlatformRsaKey key = new(CreateRsa());
		byte[] signature = CreateGuardedBuffer(0, 256);
		byte[] message = [1, 2, 3];

		using (Assert.Multiple())
		{
			foreach (SignatureAlgorithm algorithm in (SignatureAlgorithm[])[SignatureAlgorithm.EcdsaSha256, SignatureAlgorithm.MLDsa44, 0, (SignatureAlgorithm)int.MaxValue])
			{
				await Assert.That(() => key.Sign(algorithm, message, signature)).Throws<ArgumentException>().WithParameterName("algorithm");
				await Assert.That(() => key.Verify(algorithm, message, signature)).Throws<ArgumentException>().WithParameterName("algorithm");
				await Assert.That(() => key.GetMaxSignatureLength(algorithm)).Throws<ArgumentException>().WithParameterName("algorithm");
			}

			foreach (int shortfall in (int[])[1, int.MaxValue])
			{
				byte[] shortSignature = ShortBuffer(key.GetMaxSignatureLength(SignatureAlgorithm.RsaPssSha256), shortfall);
				byte[] shortSubjectPublicKeyInfo = ShortBuffer(key.SubjectPublicKeyInfoLength, shortfall);

				await Assert.That(() => key.Sign(SignatureAlgorithm.RsaPssSha256, message, shortSignature)).Throws<ArgumentException>().WithParameterName("destination");
				await Assert.That(() => key.ExportSubjectPublicKeyInfo(shortSubjectPublicKeyInfo)).Throws<ArgumentException>().WithParameterName("destination");
				await Assert.That(shortSignature).All(static value => value is DestinationSentinel);
				await Assert.That(shortSubjectPublicKeyInfo).All(static value => value is DestinationSentinel);
			}

			await Assert.That(signature).All(static value => value is DestinationSentinel);
			await Assert.That(() => new PlatformRsaKey(null!)).ThrowsExactly<ArgumentNullException>();
			await Assert.That(() => new PlatformRsaKey(null!, RsaAlgorithms)).ThrowsExactly<ArgumentNullException>();
		}
	}

	[Test]
	public async Task DisposeAlsoDisposesThePlatformKey()
	{
		TestRsa platform = new(RsaPrivateParameters());
		PlatformRsaKey key = new(platform);
		PlatformRsaKey publicKey = PlatformRsaKey.ImportSubjectPublicKeyInfo(ExportSubjectPublicKeyInfo(key));
		byte[] message = [1, 2, 3];
		byte[] signature = Sign(key, SignatureAlgorithm.RsaPssSha256, message);
		key.Dispose();
		key.Dispose();
		publicKey.Dispose();

		using (Assert.Multiple())
		{
			foreach (PlatformRsaKey disposed in (PlatformRsaKey[])[key, publicKey])
			{
				await Assert.That(() => disposed.HasPrivateKey).ThrowsExactly<ObjectDisposedException>();
				await Assert.That(() => disposed.SubjectPublicKeyInfoLength).ThrowsExactly<ObjectDisposedException>();
				await Assert.That(() => disposed.Pkcs8PrivateKeyLength).ThrowsExactly<ObjectDisposedException>();
				await Assert.That(() => disposed.Supports(SignatureAlgorithm.RsaPssSha256)).ThrowsExactly<ObjectDisposedException>();
				await Assert.That(() => disposed.GetMaxSignatureLength(SignatureAlgorithm.RsaPssSha256)).ThrowsExactly<ObjectDisposedException>();
				await Assert.That(() => disposed.Sign(SignatureAlgorithm.RsaPssSha256, message, new byte[256])).ThrowsExactly<ObjectDisposedException>();
				await Assert.That(() => disposed.Verify(SignatureAlgorithm.RsaPssSha256, message, signature)).ThrowsExactly<ObjectDisposedException>();
				await Assert.That(() => disposed.ExportSubjectPublicKeyInfo(new byte[300])).ThrowsExactly<ObjectDisposedException>();
				await Assert.That(() => disposed.ExportPkcs8PrivateKey(new byte[2000])).ThrowsExactly<ObjectDisposedException>();
			}

			await Assert.That(platform.IsDisposed).IsTrue();
		}
	}

	// Signatures on several threads reach the platform key one at a time: each waits for another to start signing, which the instance must not let happen; verification runs alongside.
	[Test]
	public async Task PassesOneSignatureAtATimeToThePlatformKey()
	{
		ObservedRsa platform = new(RsaPrivateParameters());
		platform.OnSign = () => platform.WaitForSignatures(2, TimeSpan.FromMilliseconds(100));
		using PlatformRsaKey key = new(platform, RsaAlgorithms);
		byte[] message = CreateDeterministicSource(64);

		bool[] verified = await Task.WhenAll(Enumerable.Range(0, 4).Select(i => Task.Factory.StartNew(() =>
		{
			SignatureAlgorithm algorithm = RsaAlgorithms[i % RsaAlgorithms.Length];
			return key.Verify(algorithm, message, Sign(key, algorithm, message));
		}, CancellationToken.None, TaskCreationOptions.LongRunning, TaskScheduler.Default)));

		using (Assert.Multiple())
		{
			await Assert.That(verified).All(static value => value);
			await Assert.That(platform.Signatures).IsEqualTo(4);
			await Assert.That(platform.MaxConcurrentSignatures).IsEqualTo(1);
		}
	}

	// Dispose called while the platform key signs returns only after the signature, so that the platform key is not disposed under it.
	[Test]
	public async Task DisposeWaitsForTheSignatureInProgress()
	{
		using ManualResetEventSlim signing = new();
		using ManualResetEventSlim release = new();
		ObservedRsa platform = new(RsaPrivateParameters());
		platform.OnSign = () =>
		{
			signing.Set();
			release.Wait(TimeSpan.FromSeconds(30));
		};
		PlatformRsaKey key = new(platform, RsaAlgorithms);
		using PlatformRsaKey publicKey = PlatformRsaKey.ImportSubjectPublicKeyInfo(ExportSubjectPublicKeyInfo(key));
		byte[] message = CreateDeterministicSource(64);

		Task<byte[]> sign = Task.Factory.StartNew(() => Sign(key, SignatureAlgorithm.RsaPssSha256, message), CancellationToken.None, TaskCreationOptions.LongRunning, TaskScheduler.Default);
		bool started = signing.Wait(TimeSpan.FromSeconds(30));
		Task dispose = Task.Factory.StartNew(key.Dispose, CancellationToken.None, TaskCreationOptions.LongRunning, TaskScheduler.Default);
		bool disposedDuringSignature = await Task.WhenAny(dispose, Task.Delay(TimeSpan.FromMilliseconds(200))) == dispose;
		release.Set();
		byte[] signature = await sign;
		await dispose;

		using (Assert.Multiple())
		{
			await Assert.That(started).IsTrue();
			await Assert.That(disposedDuringSignature).IsFalse();
			await Assert.That(platform.DisposedWhileSigning).IsFalse();
			await Assert.That(platform.IsDisposed).IsTrue();
			await Assert.That(publicKey.Verify(SignatureAlgorithm.RsaPssSha256, message, signature)).IsTrue();
		}
	}

	// The modulus must be 512 to 16384 bits long and the public exponent at most 33 bits, which bound the work of verification; otherwise the key must be valid (RFC 8017, Sec. 3.1). RsaKey imports
	// and refuses the same keys.
	[Test]
	public async Task PublicKeysMustBeValidAndWithinTheBounds()
	{
		BigInteger e = 65537;
		(string Case, byte[] SubjectPublicKeyInfo)[] supported =
		[
			("512-bit modulus", RsaSubjectPublicKeyInfo(Modulus(512), e)),
			("16384-bit modulus", RsaSubjectPublicKeyInfo(Modulus(16384), e)),
			("exponent 3", RsaSubjectPublicKeyInfo(Modulus(2048), 3)),
			("33-bit exponent", RsaSubjectPublicKeyInfo(Modulus(2048), (BigInteger.One << 33) - 1)),
		];
		(string Case, byte[] SubjectPublicKeyInfo)[] unsupported =
		[
			("511-bit modulus", RsaSubjectPublicKeyInfo(Modulus(511), e)),
			("16385-bit modulus", RsaSubjectPublicKeyInfo(Modulus(16385), e)),
			("34-bit exponent", RsaSubjectPublicKeyInfo(Modulus(2048), (BigInteger.One << 33) + 1)),
		];
		(string Case, byte[] SubjectPublicKeyInfo)[] invalid =
		[
			("even modulus", RsaSubjectPublicKeyInfo(Modulus(2048) - 1, e)),
			("negative modulus", RsaSubjectPublicKeyInfo(-Modulus(2048), e)),
			("zero modulus", RsaSubjectPublicKeyInfo(0, e)),
			("exponent 1", RsaSubjectPublicKeyInfo(Modulus(2048), 1)),
			("even exponent", RsaSubjectPublicKeyInfo(Modulus(2048), 65536)),
			("negative exponent", RsaSubjectPublicKeyInfo(Modulus(2048), -e)),
			("rsaEncryption without parameters", RsaSubjectPublicKeyInfo(Modulus(2048), e, Sequence(Oid("1.2.840.113549.1.1.1")))),
			("rsaEncryption with other parameters", RsaSubjectPublicKeyInfo(Modulus(2048), e, Sequence(Oid("1.2.840.113549.1.1.1"), [0x04, 0x00]))),
			("id-ecPublicKey", RsaSubjectPublicKeyInfo(Modulus(2048), e, Sequence(Oid("1.2.840.10045.2.1"), Oid("1.2.840.10045.3.1.7")))),
			("trailing byte", [.. RsaSubjectPublicKeyInfo(Modulus(2048), e), 0x00]),
			("RSAPublicKey with a third INTEGER", Sequence(RsaEncryption, Tlv(0x03, [0x00], Sequence(Integer(Modulus(2048)), Integer(e), Integer(e))))),
			("RSAPublicKey with a trailing byte", Sequence(RsaEncryption, Tlv(0x03, [0x00], [.. Sequence(Integer(Modulus(2048)), Integer(e)), 0x00]))),
			("long-form length", WithRedundantLengthByte(RsaSubjectPublicKeyInfo(Modulus(2048), e))),
			("RSASSA-PSS parameters that are not RSASSA-PSS-params", Sequence(Sequence(Oid("1.2.840.113549.1.1.10"), [0x05, 0x00]), Tlv(0x03, [0x00], Sequence(Integer(Modulus(2048)), Integer(e))))),
		];

		using (Assert.Multiple())
		{
			foreach ((string @case, byte[] subjectPublicKeyInfo) in supported)
			{
				using PlatformRsaKey key = PlatformRsaKey.ImportSubjectPublicKeyInfo(subjectPublicKeyInfo);
				await Assert.That(ExportSubjectPublicKeyInfo(key)).IsEquivalentTo(subjectPublicKeyInfo, CollectionOrdering.Matching).Because(@case);
				await Assert.That(key.Verify(SignatureAlgorithm.RsaPkcs1Sha256, [1], CreateDeterministicSource(key.GetMaxSignatureLength(SignatureAlgorithm.RsaPkcs1Sha256)))).IsFalse().Because(@case);
				using RsaKey rsaKey = RsaKey.ImportSubjectPublicKeyInfo(subjectPublicKeyInfo);
				await Assert.That(RsaAlgorithms.Where(rsaKey.Supports)).IsEquivalentTo(RsaAlgorithms.Where(key.Supports), CollectionOrdering.Matching).Because(@case);
			}

			foreach ((string @case, byte[] subjectPublicKeyInfo) in unsupported)
			{
				await Assert.That(() => PlatformRsaKey.ImportSubjectPublicKeyInfo(subjectPublicKeyInfo)).ThrowsExactly<NotSupportedException>().Because(@case);
				await Assert.That(() => RsaKey.ImportSubjectPublicKeyInfo(subjectPublicKeyInfo)).ThrowsExactly<NotSupportedException>().Because(@case);
			}

			foreach ((string @case, byte[] subjectPublicKeyInfo) in invalid)
			{
				await Assert.That(() => PlatformRsaKey.ImportSubjectPublicKeyInfo(subjectPublicKeyInfo)).Throws<ArgumentException>().WithParameterName("source").Because(@case);
				await Assert.That(() => RsaKey.ImportSubjectPublicKeyInfo(subjectPublicKeyInfo)).Throws<ArgumentException>().WithParameterName("source").Because(@case);
			}
		}
	}

	// A platform key is held to the same rules, and stays with the caller when it breaks them.
	[Test]
	public async Task PlatformKeysMustBeValidAndWithinTheBounds()
	{
		(string Case, BigInteger Modulus, BigInteger Exponent, Type Exception)[] cases =
		[
			("511-bit modulus", Modulus(511), 65537, typeof(NotSupportedException)),
			("16385-bit modulus", Modulus(16385), 65537, typeof(NotSupportedException)),
			("34-bit exponent", Modulus(2048), (BigInteger.One << 33) + 1, typeof(NotSupportedException)),
			("even modulus", Modulus(2048) - 1, 65537, typeof(ArgumentException)),
			("even exponent", Modulus(2048), 65536, typeof(ArgumentException)),
			("exponent 1", Modulus(2048), 1, typeof(ArgumentException)),
		];

		using (Assert.Multiple())
		{
			foreach ((string @case, BigInteger modulus, BigInteger exponent, Type exception) in cases)
			{
				using TestRsa platform = new(new RSAParameters { Modulus = modulus.ToByteArray(true, true), Exponent = exponent.ToByteArray(true, true) });

				if (exception == typeof(NotSupportedException))
				{
					await Assert.That(() => new PlatformRsaKey(platform)).ThrowsExactly<NotSupportedException>().Because(@case);
					await Assert.That(() => new PlatformRsaKey(platform, RsaAlgorithms)).ThrowsExactly<NotSupportedException>().Because(@case);
				}
				else
				{
					await Assert.That(() => new PlatformRsaKey(platform)).Throws<ArgumentException>().WithParameterName("key").Because(@case);
					await Assert.That(() => new PlatformRsaKey(platform, RsaAlgorithms)).Throws<ArgumentException>().WithParameterName("key").Because(@case);
				}

				await Assert.That(platform.IsDisposed).IsFalse();
			}
		}
	}

	// The thresholds of RFC 8017: k ≥ 19 + hLen + 11 bytes for RSASSA-PKCS1-v1_5 (Sec. 9.2) and ⌈(modBits − 1)/8⌉ ≥ 2hLen + 2 for RSASSA-PSS (Sec. 9.1.1).
	[Test]
	[Arguments(512, "RsaPkcs1Sha256")]
	[Arguments(521, "RsaPkcs1Sha256")]
	[Arguments(522, "RsaPkcs1Sha256 RsaPssSha256")]
	[Arguments(616, "RsaPkcs1Sha256 RsaPssSha256")]
	[Arguments(617, "RsaPkcs1Sha256 RsaPkcs1Sha384 RsaPssSha256")]
	[Arguments(744, "RsaPkcs1Sha256 RsaPkcs1Sha384 RsaPssSha256")]
	[Arguments(745, "RsaPkcs1Sha256 RsaPkcs1Sha384 RsaPkcs1Sha512 RsaPssSha256")]
	[Arguments(777, "RsaPkcs1Sha256 RsaPkcs1Sha384 RsaPkcs1Sha512 RsaPssSha256")]
	[Arguments(778, "RsaPkcs1Sha256 RsaPkcs1Sha384 RsaPkcs1Sha512 RsaPssSha256 RsaPssSha384")]
	[Arguments(1033, "RsaPkcs1Sha256 RsaPkcs1Sha384 RsaPkcs1Sha512 RsaPssSha256 RsaPssSha384")]
	[Arguments(1034, "RsaPkcs1Sha256 RsaPkcs1Sha384 RsaPkcs1Sha512 RsaPssSha256 RsaPssSha384 RsaPssSha512")]
	public async Task TheModulusDecidesTheAlgorithms(int bits, string expected)
	{
		using PlatformRsaKey key = PlatformRsaKey.ImportSubjectPublicKeyInfo(RsaSubjectPublicKeyInfo(Modulus(bits), 65537));

		await Assert.That(string.Join(' ', RsaAlgorithms.Where(key.Supports))).IsEqualTo(expected);
	}

	// An id-RSASSA-PSS key signs with RSASSA-PSS alone; with parameters, only with their hash and MGF1 with it, and a salt at least as long as their saltLength (RFC 4055, Sec. 3.3). RsaKey
	// imports and refuses the same keys.
	[Test]
	public async Task RsassaPssKeysAllowWhatTheirParametersAllow()
	{
		(string Case, byte[] Algorithm, SignatureAlgorithm[] Allowed)[] supported =
		[
			("no parameters", RsassaPssIdentifier(withParameters: false), [SignatureAlgorithm.RsaPssSha256, SignatureAlgorithm.RsaPssSha384, SignatureAlgorithm.RsaPssSha512]),
			("SHA-256", RsassaPssIdentifier(), [SignatureAlgorithm.RsaPssSha256]),
			("SHA-384", RsassaPssIdentifier(hash: Sha384Oid, maskHash: Sha384Oid, saltLength: 48), [SignatureAlgorithm.RsaPssSha384]),
			("SHA-512", RsassaPssIdentifier(hash: Sha512Oid, maskHash: Sha512Oid, saltLength: 64), [SignatureAlgorithm.RsaPssSha512]),
			("default saltLength of 20", RsassaPssIdentifier(saltLength: null), [SignatureAlgorithm.RsaPssSha256]),
			("saltLength 0", RsassaPssIdentifier(saltLength: 0), [SignatureAlgorithm.RsaPssSha256]),
			("absent hash parameters", RsassaPssIdentifier(nullParameters: false, maskNullParameters: false), [SignatureAlgorithm.RsaPssSha256]),
			("explicit trailer field", RsassaPssIdentifier(trailerField: 1), [SignatureAlgorithm.RsaPssSha256]),
		];
		(string Case, byte[] Algorithm)[] unsupported =
		[
			("saltLength longer than the hash", RsassaPssIdentifier(saltLength: 33)),
			("default hash, SHA-1", RsassaPssIdentifier(hash: null)),
			("default mask generation function, MGF1 with SHA-1", RsassaPssIdentifier(maskHash: null)),
			("MGF1 with another hash", RsassaPssIdentifier(hash: Sha512Oid, saltLength: 64)),
			("SHA-1", RsassaPssIdentifier(hash: "1.3.14.3.2.26", maskHash: "1.3.14.3.2.26", saltLength: 20)),
			("another mask generation function", RsassaPssIdentifier(maskGenerationFunction: "1.2.840.113549.1.1.99")),
			("trailer field 2", RsassaPssIdentifier(trailerField: 2)),
			("negative saltLength", RsassaPssIdentifier(saltLength: -1)),
		];
		BigInteger modulus = Modulus(2048);

		using (Assert.Multiple())
		{
			foreach ((string @case, byte[] algorithm, SignatureAlgorithm[] allowed) in supported)
			{
				byte[] subjectPublicKeyInfo = RsaSubjectPublicKeyInfo(modulus, 65537, algorithm);
				using PlatformRsaKey key = PlatformRsaKey.ImportSubjectPublicKeyInfo(subjectPublicKeyInfo);
				await Assert.That(RsaAlgorithms.Where(key.Supports)).IsEquivalentTo(allowed, CollectionOrdering.Matching).Because(@case);
				await Assert.That(ExportSubjectPublicKeyInfo(key)).IsEquivalentTo(subjectPublicKeyInfo, CollectionOrdering.Matching).Because(@case);
				using RsaKey rsaKey = RsaKey.ImportSubjectPublicKeyInfo(subjectPublicKeyInfo);
				await Assert.That(RsaAlgorithms.Where(rsaKey.Supports)).IsEquivalentTo(allowed, CollectionOrdering.Matching).Because(@case);
				await Assert.That(ExportSubjectPublicKeyInfo(rsaKey)).IsEquivalentTo(subjectPublicKeyInfo, CollectionOrdering.Matching).Because(@case);
			}

			foreach ((string @case, byte[] algorithm) in unsupported)
			{
				await Assert.That(() => PlatformRsaKey.ImportSubjectPublicKeyInfo(RsaSubjectPublicKeyInfo(modulus, 65537, algorithm))).ThrowsExactly<NotSupportedException>().Because(@case);
				await Assert.That(() => RsaKey.ImportSubjectPublicKeyInfo(RsaSubjectPublicKeyInfo(modulus, 65537, algorithm))).ThrowsExactly<NotSupportedException>().Because(@case);
			}
		}
	}

	// RFC 8017, Sec. 9.1.2, for keys whose EM fills its bytes but for one bit (2048), whose EM is a byte shorter than the modulus (1025), and whose EM leaves 7 bits unused (1026).
	[Test]
	[Arguments(2048)]
	[Arguments(1025)]
	[Arguments(1026)]
	public async Task RsassaPssVerificationFollowsRfc8017(int bits)
	{
		RSAParameters parameters = bits switch
		{
			1025 => Key1025,
			1026 => Key1026,
			_ => RsaPrivateParameters(bits)
		};
		using PlatformRsaKey key = PlatformRsaKey.ImportSubjectPublicKeyInfo(RsaSubjectPublicKeyInfo(new BigInteger(parameters.Modulus, true, true), new BigInteger(parameters.Exponent, true, true)));
		byte[] message = "message"u8.ToArray();
		byte[] mHash = SHA256.HashData(message);
		int zeroBits = 8 * ((bits + 6) / 8) - (bits - 1);
		BigInteger modulus = new(parameters.Modulus, true, true);
		List<(string Case, byte[] EncodedMessage)> invalid =
		[
			("salt of 0 bytes", EncodePss(bits, HashAlgorithmName.SHA256, mHash, 0)),
			("salt of 20 bytes", EncodePss(bits, HashAlgorithmName.SHA256, mHash, 20)),
			("salt of 33 bytes", EncodePss(bits, HashAlgorithmName.SHA256, mHash, 33)),
			("trailer field 0xCC", EncodePss(bits, HashAlgorithmName.SHA256, mHash, 32, trailer: 0xCC)),
			("MGF1 with SHA-1", EncodePss(bits, HashAlgorithmName.SHA256, mHash, 32, maskHash: HashAlgorithmName.SHA1)),
			("0x02 after the padding", EncodePss(bits, HashAlgorithmName.SHA256, mHash, 32, changeDb: static db => db[^33] = 0x02)),
			("nonzero padding", EncodePss(bits, HashAlgorithmName.SHA256, mHash, 32, changeDb: static db => db[1] = 0x01)),
			("another message", EncodePss(bits, HashAlgorithmName.SHA256, SHA256.HashData("massage"u8), 32)),
			("SHA-384", EncodePss(bits, HashAlgorithmName.SHA384, SHA384.HashData(message), 32)),
			("RSASSA-PKCS1-v1_5", EncodePkcs1((bits + 6) / 8, DigestInfo(Sha256Oid, mHash))),
		];

		if (zeroBits > 0)
		{
			// The lowest of the bits that must be zero (step 6), in an EM below the modulus, so that a signature gives it.
			byte topBit = (byte)(0x80 >> zeroBits - 1);
			byte[] encodedMessage;

			do
			{
				encodedMessage = EncodePss(bits, HashAlgorithmName.SHA256, mHash, 32, topBits: topBit);
			}
			while (new BigInteger(encodedMessage, true, true) >= modulus);

			invalid.Add(("a bit beyond emBits", encodedMessage));
		}

		byte[] valid = RawSign(parameters, EncodePss(bits, HashAlgorithmName.SHA256, mHash, 32));

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
				await Assert.That(key.Verify(SignatureAlgorithm.RsaPssSha256, message, I2Osp(modulus - 1, valid.Length))).IsFalse();
			}

			foreach (byte[] signature in (byte[][])[I2Osp(modulus, valid.Length), I2Osp(modulus + 1, valid.Length), Enumerable.Repeat((byte)0xFF, valid.Length).ToArray(), new byte[valid.Length], valid.AsSpan(1).ToArray(), [0x00, .. valid]])
			{
				await Assert.That(key.Verify(SignatureAlgorithm.RsaPssSha256, message, signature)).IsFalse().Because(Convert.ToHexString(signature.AsSpan(0, 4)));
			}
		}

		// The platform's RSA, as an independent check, verifies the valid signature too.
		if (bits is 2048)
		{
			using RSA bcl = CreateRsa();
			await Assert.That(bcl.VerifyData(message, valid, HashAlgorithmName.SHA256, RSASignaturePadding.Pss)).IsTrue();
		}
	}

	// RFC 8017, Sec. 8.2.2: the encoded message must equal EMSA-PKCS1-V1_5-ENCODE of the message, whose DigestInfo has NULL or absent parameters (RFC 5246, Sec. 4.7).
	[Test]
	[Arguments(2048)]
	[Arguments(1025)]
	public async Task RsassaPkcs1VerificationComparesTheWholeEncoding(int bits)
	{
		RSAParameters parameters = bits is 1025 ? Key1025 : RsaPrivateParameters(bits);
		using PlatformRsaKey key = PlatformRsaKey.ImportSubjectPublicKeyInfo(RsaSubjectPublicKeyInfo(new BigInteger(parameters.Modulus, true, true), new BigInteger(parameters.Exponent, true, true)));
		int length = (bits + 7) / 8;
		byte[] message = "message"u8.ToArray();
		byte[] digest = SHA256.HashData(message);
		byte[] digestInfo = DigestInfo(Sha256Oid, digest);
		byte[] withoutNull = Sequence(Sequence(Oid(Sha256Oid)), Tlv(0x04, digest));
		byte[] valid = EncodePkcs1(length, digestInfo);
		(string Case, byte[] EncodedMessage)[] invalid =
		[
			("DigestInfo without parameters, with a long-form length", EncodePkcs1(length, WithRedundantLengthByte(withoutNull))),
			("DigestInfo with a long-form length", EncodePkcs1(length, WithRedundantLengthByte(digestInfo))),
			("DigestInfo of SHA-384", EncodePkcs1(length, DigestInfo(Sha384Oid, SHA384.HashData(message)))),
			("hash of another message", EncodePkcs1(length, DigestInfo(Sha256Oid, SHA256.HashData("massage"u8)))),
			("block type 2", [.. valid.AsSpan(0, 1), 0x02, .. valid.AsSpan(2)]),
			("0xFE in the padding", [.. valid.AsSpan(0, 5), 0xFE, .. valid.AsSpan(6)]),
			("no separator", [.. valid.AsSpan(0, length - digestInfo.Length - 1), 0xFF, .. digestInfo]),
			("padding cut short by a garbage byte", [0x00, 0x01, .. Enumerable.Repeat((byte)0xFF, length - digestInfo.Length - 5), 0x00, 0x00, 0x00, .. digestInfo]),
			("RSASSA-PSS", EncodePss(bits, HashAlgorithmName.SHA256, digest, 32)),
		];

		using (Assert.Multiple())
		{
			await Assert.That(key.Verify(SignatureAlgorithm.RsaPkcs1Sha256, message, RawSign(parameters, valid))).IsTrue();
			await Assert.That(key.Verify(SignatureAlgorithm.RsaPkcs1Sha256, message, RawSign(parameters, EncodePkcs1(length, withoutNull)))).IsTrue();

			foreach ((string @case, byte[] encodedMessage) in invalid)
			{
				await Assert.That(key.Verify(SignatureAlgorithm.RsaPkcs1Sha256, message, RawSign(parameters, encodedMessage))).IsFalse().Because(@case);
			}
		}
	}

	// Wycheproof RSASSA-PKCS1-v1_5 and RSASSA-PSS vectors. A vector verifies only with the SignatureAlgorithm of its hash, MGF1 with the same hash and a salt as long as the hash: in a group with another salt
	// length, only the invalid vector that the file made with a salt as long as the hash. An id-RSASSA-PSS key with parameters is supported if they allow such an algorithm (RFC 4055, Sec. 3.3). The
	// acceptable vectors, whose DigestInfo lacks the NULL parameters, verify.
	[Test]
	[Arguments("rsa_signature_2048_sha256_test.json")]
	[Arguments("rsa_signature_2048_sha384_test.json")]
	[Arguments("rsa_signature_2048_sha512_test.json")]
	[Arguments("rsa_signature_3072_sha256_test.json")]
	[Arguments("rsa_signature_3072_sha384_test.json")]
	[Arguments("rsa_signature_3072_sha512_test.json")]
	[Arguments("rsa_signature_4096_sha256_test.json")]
	[Arguments("rsa_signature_4096_sha384_test.json")]
	[Arguments("rsa_signature_4096_sha512_test.json")]
	[Arguments("rsa_signature_8192_sha256_test.json")]
	[Arguments("rsa_signature_8192_sha384_test.json")]
	[Arguments("rsa_signature_8192_sha512_test.json")]
	[Arguments("rsa_pss_2048_sha1_mgf1_20_params_test.json")]
	[Arguments("rsa_pss_2048_sha256_mgf1_0_params_test.json")]
	[Arguments("rsa_pss_2048_sha256_mgf1_0_test.json")]
	[Arguments("rsa_pss_2048_sha256_mgf1_32_params_test.json")]
	[Arguments("rsa_pss_2048_sha256_mgf1_32_test.json")]
	[Arguments("rsa_pss_2048_sha256_mgf1sha1_20_test.json")]
	[Arguments("rsa_pss_2048_sha384_mgf1_48_test.json")]
	[Arguments("rsa_pss_2048_sha512_mgf1sha256_32_params_test.json")]
	[Arguments("rsa_pss_3072_sha256_mgf1_32_params_test.json")]
	[Arguments("rsa_pss_3072_sha256_mgf1_32_test.json")]
	[Arguments("rsa_pss_4096_sha256_mgf1_32_test.json")]
	[Arguments("rsa_pss_4096_sha384_mgf1_48_test.json")]
	[Arguments("rsa_pss_4096_sha512_mgf1_32_params_test.json")]
	[Arguments("rsa_pss_4096_sha512_mgf1_32_test.json")]
	[Arguments("rsa_pss_4096_sha512_mgf1_64_params_test.json")]
	[Arguments("rsa_pss_4096_sha512_mgf1_64_test.json")]
	[Arguments("rsa_pss_misc_params_test.json")]
	[Arguments("rsa_pss_misc_test.json")]
	public async Task WycheproofVectorsVerify(string fileName)
	{
		using JsonDocument document = JsonDocument.Parse(File.ReadAllBytes(WycheproofPath(fileName)));
		int groups = 0;

		using (Assert.Multiple())
		{
			foreach (JsonElement group in document.RootElement.GetProperty("testGroups").EnumerateArray())
			{
				string type = group.GetProperty("type").GetString() ?? "";
				bool pss = type is not "RsassaPkcs1Verify";
				(SignatureAlgorithm algorithm, int hashLength) = WycheproofAlgorithm(group.GetProperty("sha").GetString(), pss);
				bool sameHashes = !pss || group.GetProperty("mgfSha").GetString() == group.GetProperty("sha").GetString();
				int saltLength = pss ? group.GetProperty("sLen").GetInt32() : 0;
				byte[] subjectPublicKeyInfo = Convert.FromHexString(group.GetProperty("publicKeyDer").GetString() ?? "");
				string context = $"{fileName}, group of {group.GetProperty("sha")} {(pss ? $"{group.GetProperty("mgfSha")} {saltLength}" : "")}";
				++groups;

				if (type is "RsassaPssWithParametersVerify" && !(algorithm is not 0 && sameHashes && saltLength <= hashLength))
				{
					await Assert.That(() => PlatformRsaKey.ImportSubjectPublicKeyInfo(subjectPublicKeyInfo)).ThrowsExactly<NotSupportedException>().Because(context);
					continue;
				}

				using PlatformRsaKey key = PlatformRsaKey.ImportSubjectPublicKeyInfo(subjectPublicKeyInfo);

				if (algorithm is 0)
				{
					continue;
				}

				SignatureAlgorithm[] expectedAlgorithms = type is "RsassaPssWithParametersVerify" ? [algorithm] : RsaAlgorithms;
				await Assert.That(RsaAlgorithms.Where(key.Supports)).IsEquivalentTo(expectedAlgorithms, CollectionOrdering.Matching).Because(context);

				foreach (JsonElement test in group.GetProperty("tests").EnumerateArray())
				{
					string result = test.GetProperty("result").GetString() ?? "";
					string[] flags = [.. test.GetProperty("flags").EnumerateArray().Select(static flag => flag.GetString() ?? "")];
					bool expected = sameHashes && (!pss || saltLength == hashLength ? result is "valid" or "acceptable" : test.GetProperty("comment").GetString() == $"s_len changed to {hashLength}");
					byte[] message = Convert.FromHexString(test.GetProperty("msg").GetString() ?? "");
					byte[] signature = Convert.FromHexString(test.GetProperty("sig").GetString() ?? "");

					if (result is "acceptable")
					{
						await Assert.That(flags).IsEquivalentTo(["MissingNull"]).Because($"{context}, tcId {test.GetProperty("tcId")}");
					}

					await Assert.That(key.Verify(algorithm, message, signature)).IsEqualTo(expected).Because($"{context}, tcId {test.GetProperty("tcId")}: {string.Join(", ", flags)}");
				}
			}

			await Assert.That(groups).IsGreaterThan(0);
		}
	}

	// The RSA signature files of Wycheproof: RSASSA-PKCS1-v1_5 generation and verification, and RSASSA-PSS verification.
	public static IEnumerable<Func<string>> WycheproofSignatureFiles()
	{
		return Directory.EnumerateFiles(WycheproofPath(""), "rsa_*_test.json")
			.Select(Path.GetFileName)
			.OfType<string>()
			.Where(static fileName => fileName.StartsWith("rsa_signature_", StringComparison.Ordinal) || fileName.StartsWith("rsa_pss_", StringComparison.Ordinal) || fileName.EndsWith("_sig_gen_test.json", StringComparison.Ordinal))
			.Order(StringComparer.Ordinal)
			.Select(static fileName => (Func<string>)(() => fileName));
	}

	// PlatformRsaKey and RsaKey import the same keys of every vector, or both throw the same exception, support the same algorithms, export the same SubjectPublicKeyInfo, and verify each signature
	// alike with the algorithm of its group where they support it, and otherwise with one that they do.
	[Test]
	[MethodDataSource(nameof(WycheproofSignatureFiles))]
	public async Task VerifiesWycheproofVectorsAsRsaKeyDoes(string fileName)
	{
		IEnumerable<RsaSignatureTestVector> vectors = fileName.EndsWith("_sig_gen_test.json", StringComparison.Ordinal)
			? WycheproofVectors.Load<RsaSignTestGroup, RsaSignatureTestVector>(fileName)
			: WycheproofVectors.Load<RsaVerifyTestGroup, RsaSignatureTestVector>(fileName);
		List<string> differences = [];
		int groups = 0;

		// The vectors of a group share its SubjectPublicKeyInfo.
		foreach (IGrouping<byte[], RsaSignatureTestVector> group in vectors.GroupBy(static vector => vector.PublicKeyDer))
		{
			string context = $"{fileName}, {group.First()}";
			++groups;
			(PlatformRsaKey? platformKey, Type? platformException) = Import(static subjectPublicKeyInfo => PlatformRsaKey.ImportSubjectPublicKeyInfo(subjectPublicKeyInfo), group.Key);
			(RsaKey? key, Type? exception) = Import(static subjectPublicKeyInfo => RsaKey.ImportSubjectPublicKeyInfo(subjectPublicKeyInfo), group.Key);

			using (platformKey)
			using (key)
			{
				if (platformKey is null || key is null)
				{
					if (platformException != exception)
					{
						differences.Add($"{context}: PlatformRsaKey {platformException?.Name ?? "imports"}, RsaKey {exception?.Name ?? "imports"}");
					}

					continue;
				}

				SignatureAlgorithm[] algorithms = [.. RsaAlgorithms.Where(platformKey.Supports)];

				if (!algorithms.SequenceEqual(RsaAlgorithms.Where(key.Supports)))
				{
					differences.Add($"{context}: PlatformRsaKey supports [{string.Join(", ", algorithms)}], RsaKey [{string.Join(", ", RsaAlgorithms.Where(key.Supports))}]");
				}

				if (!ExportSubjectPublicKeyInfo(platformKey).AsSpan().SequenceEqual(ExportSubjectPublicKeyInfo(key)))
				{
					differences.Add($"{context}: the SubjectPublicKeyInfo differs");
				}

				if (algorithms is [])
				{
					continue;
				}

				foreach (RsaSignatureTestVector vector in group)
				{
					SignatureAlgorithm own = WycheproofAlgorithm(vector.Sha, vector.GroupType.StartsWith("RsassaPss", StringComparison.Ordinal)).Algorithm;
					SignatureAlgorithm algorithm = algorithms.Contains(own) ? own : algorithms[0];
					bool platform = platformKey.Verify(algorithm, vector.Msg, vector.Sig);

					if (platform != key.Verify(algorithm, vector.Msg, vector.Sig))
					{
						differences.Add($"{vector}, {algorithm}: PlatformRsaKey {platform}, RsaKey {!platform}");
					}
				}
			}
		}

		using (Assert.Multiple())
		{
			await Assert.That(groups).IsGreaterThan(0);
			await Assert.That(differences).IsEmpty().Because(string.Join(Environment.NewLine, differences.Take(20)));
		}

		static (T? Key, Type? Exception) Import<T>(Func<byte[], T> import, byte[] subjectPublicKeyInfo) where T : class
		{
			try
			{
				return (import(subjectPublicKeyInfo), null);
			}
			catch (Exception e) when (e is ArgumentException or NotSupportedException or CryptographicException)
			{
				return (null, e.GetType());
			}
		}
	}

	// Certificates whose RSASSA-PSS-params have hash AlgorithmIdentifiers with NULL parameters and without parameters; RsaKey imports their keys with the same algorithms, and verifies them too.
	[Test]
	public async Task VerifiesCertificatesOfOpenSslAndTheBcl()
	{
		using RSA bclKey = CreateRsa();
		List<(string Case, Certificate Certificate, SignatureAlgorithm[] KeyAlgorithms)> certificates =
		[
			("OpenSSL, RSASSA-PSS with SHA-256", Certificate.DecodePem(OpenSslCertificates.RsaPssSha256), RsaAlgorithms),
			("OpenSSL, RSASSA-PKCS1-v1_5 with SHA-384", Certificate.DecodePem(OpenSslCertificates.RsaPkcs1Sha384), RsaAlgorithms),
			("OpenSSL, id-RSASSA-PSS key with parameters", Certificate.DecodePem(OpenSslCertificates.RsassaPssKeySha512), [SignatureAlgorithm.RsaPssSha512]),
			("OpenSSL, id-RSASSA-PSS key without parameters", Certificate.DecodePem(OpenSslCertificates.RsassaPssKeyWithoutParametersSha384), [SignatureAlgorithm.RsaPssSha256, SignatureAlgorithm.RsaPssSha384, SignatureAlgorithm.RsaPssSha512]),
		];

		foreach (SignatureAlgorithm algorithm in RsaAlgorithms)
		{
			using X509Certificate2 bcl = BclSelfSigned(bclKey, algorithm);
			certificates.Add(($"BCL, {algorithm}", Certificate.Decode(bcl.RawData), RsaAlgorithms));
		}

		using (Assert.Multiple())
		{
			foreach ((string @case, Certificate certificate, SignatureAlgorithm[] keyAlgorithms) in certificates)
			{
				using PlatformRsaKey key = PlatformRsaKey.ImportSubjectPublicKeyInfo(certificate.PublicKeyInfo.Encoded.Span);
				using RsaKey rsaKey = RsaKey.ImportSubjectPublicKeyInfo(certificate.PublicKeyInfo.Encoded.Span);
				byte[] tampered = certificate.Encoded.ToArray();
				tampered[^1] ^= 1;

				await Assert.That(RsaAlgorithms.Where(key.Supports)).IsEquivalentTo(keyAlgorithms, CollectionOrdering.Matching).Because(@case);
				await Assert.That(RsaAlgorithms.Where(rsaKey.Supports)).IsEquivalentTo(keyAlgorithms, CollectionOrdering.Matching).Because(@case);
				await Assert.That(certificate.VerifySignature(key)).IsTrue().Because(@case);
				await Assert.That(certificate.VerifySignature(rsaKey)).IsTrue().Because(@case);
				await Assert.That(Certificate.Decode(tampered).VerifySignature(key)).IsFalse().Because(@case);
				await Assert.That(Certificate.Decode(tampered).VerifySignature(rsaKey)).IsFalse().Because(@case);
			}
		}
	}

	private static string WycheproofPath(string fileName)
	{
		string directory = typeof(PlatformRsaKeyTest).Assembly.GetCustomAttributes<AssemblyMetadataAttribute>().Single(static attribute => attribute.Key is "WycheproofTestVectors").Value ?? "";
		return Path.Combine(directory, fileName);
	}

	// The algorithm of a Wycheproof group's hash and its length, or 0 for a hash without one.
	private static (SignatureAlgorithm Algorithm, int HashLength) WycheproofAlgorithm(string? sha, bool pss)
	{
		return (sha, pss) switch
		{
			("SHA-256", false) => (SignatureAlgorithm.RsaPkcs1Sha256, 32),
			("SHA-384", false) => (SignatureAlgorithm.RsaPkcs1Sha384, 48),
			("SHA-512", false) => (SignatureAlgorithm.RsaPkcs1Sha512, 64),
			("SHA-256", true) => (SignatureAlgorithm.RsaPssSha256, 32),
			("SHA-384", true) => (SignatureAlgorithm.RsaPssSha384, 48),
			("SHA-512", true) => (SignatureAlgorithm.RsaPssSha512, 64),
			_ => (0, 0)
		};
	}

	// A deterministic odd modulus of bits bits; not a product of two primes, which only signing needs.
	private static BigInteger Modulus(int bits)
	{
		return BigInteger.One << bits - 1 | new BigInteger(CreateDeterministicSource((bits - 1) / 8), isUnsigned: true, isBigEndian: true) | 1;
	}

	private static byte[] Integer(BigInteger value)
	{
		AsnWriter writer = new(AsnEncodingRules.DER);
		writer.WriteInteger(value);
		return writer.Encode();
	}

	private static byte[] RsaSubjectPublicKeyInfo(BigInteger modulus, BigInteger exponent, byte[]? algorithm = null)
	{
		return Sequence(algorithm ?? RsaEncryption, Tlv(0x03, [0x00], Sequence(Integer(modulus), Integer(exponent))));
	}

	private static RSAParameters ReadRsaPrivateKey(string base64)
	{
		AsnReader key = new AsnReader(Convert.FromBase64String(base64), AsnEncodingRules.DER).ReadSequence();
		key.ReadInteger();
		BigInteger modulus = key.ReadInteger();
		BigInteger exponent = key.ReadInteger();
		BigInteger d = key.ReadInteger();
		return new RSAParameters { Modulus = modulus.ToByteArray(true, true), Exponent = exponent.ToByteArray(true, true), D = d.ToByteArray(true, true) };
	}

	private static byte[] I2Osp(BigInteger value, int length)
	{
		byte[] bytes = value.ToByteArray(true, true);
		return [.. new byte[length - bytes.Length], .. bytes];
	}

	// RSASP1 (RFC 8017, Sec. 5.2.1) on an encoded message, which need not be valid.
	private static byte[] RawSign(RSAParameters parameters, byte[] encodedMessage)
	{
		BigInteger modulus = new(parameters.Modulus, true, true);
		return I2Osp(BigInteger.ModPow(new BigInteger(encodedMessage, true, true), new BigInteger(parameters.D, true, true), modulus), parameters.Modulus!.Length);
	}

	private static byte[] DigestInfo(string hash, byte[] digest)
	{
		return Sequence(Sequence(Oid(hash), [0x05, 0x00]), Tlv(0x04, digest));
	}

	// EM = 0x00 || 0x01 || PS || 0x00 || T (RFC 8017, Sec. 9.2).
	private static byte[] EncodePkcs1(int length, byte[] digestInfo)
	{
		return [0x00, 0x01, .. Enumerable.Repeat((byte)0xFF, length - digestInfo.Length - 3), 0x00, .. digestInfo];
	}

	// EMSA-PSS-ENCODE (RFC 8017, Sec. 9.1.1) with emBits = modBits − 1 and MGF1, written here apart from the code under test, with the changes that a case makes: DB before masking, the mask's hash, the bits beyond emBits and the trailer field.
	private static byte[] EncodePss(int modulusBits, HashAlgorithmName hash, byte[] mHash, int saltLength, byte trailer = 0xBC, Action<byte[]>? changeDb = null, HashAlgorithmName? maskHash = null, byte topBits = 0)
	{
		int emBits = modulusBits - 1;
		int emLength = (emBits + 7) / 8;
		byte[] salt = RandomNumberGenerator.GetBytes(saltLength);
		byte[] h = CryptographicOperations.HashData(hash, [.. new byte[8], .. mHash, .. salt]);
		byte[] db = new byte[emLength - h.Length - 1];
		db[db.Length - saltLength - 1] = 0x01;
		salt.CopyTo(db, db.Length - saltLength);
		changeDb?.Invoke(db);
		HashAlgorithmName mgfHash = maskHash ?? hash;
		byte[] mask = [];

		for (uint counter = 0; mask.Length < db.Length; ++counter)
		{
			mask = [.. mask, .. CryptographicOperations.HashData(mgfHash, [.. h, (byte)(counter >> 24), (byte)(counter >> 16), (byte)(counter >> 8), (byte)counter])];
		}

		for (int i = 0; i < db.Length; ++i)
		{
			db[i] ^= mask[i];
		}

		db[0] &= (byte)(0xFF >> 8 * emLength - emBits);
		db[0] |= topBits;
		return [.. db, .. h, trailer];
	}

	// A platform key that signs with an RSA key of the BCL and calls OnSign during each signature, and records how many signatures overlap, as a key store or device that needs one signature at a time would see them. It records too whether it is disposed during a signature.
	private sealed class ObservedRsa(RSAParameters parameters) : RSA
	{
		private readonly RSA _key = Create(parameters);
		private int _signing;
		private int _signatures;
		private int _maxConcurrentSignatures;
		private bool _disposedWhileSigning;
		private bool _isDisposed;

		public Action? OnSign { get; set; }

		public int Signatures => Volatile.Read(ref _signatures);

		public int MaxConcurrentSignatures => Volatile.Read(ref _maxConcurrentSignatures);

		public bool DisposedWhileSigning => Volatile.Read(ref _disposedWhileSigning);

		public bool IsDisposed => Volatile.Read(ref _isDisposed);

		// Whether count signatures overlap before the timeout.
		public bool WaitForSignatures(int count, TimeSpan timeout)
		{
			return SpinWait.SpinUntil(() => Volatile.Read(ref _signing) >= count, timeout);
		}

		public override RSAParameters ExportParameters(bool includePrivateParameters)
		{
			return includePrivateParameters ? throw new CryptographicException("The key is not exportable.") : _key.ExportParameters(false);
		}

		public override void ImportParameters(RSAParameters parameters)
		{
			throw new NotSupportedException();
		}

		public override byte[] SignHash(byte[] hash, HashAlgorithmName hashAlgorithm, RSASignaturePadding padding)
		{
			int signing = Interlocked.Increment(ref _signing);
			Interlocked.Increment(ref _signatures);

			try
			{
				for (int max = Volatile.Read(ref _maxConcurrentSignatures); signing > max; max = Volatile.Read(ref _maxConcurrentSignatures))
				{
					Interlocked.CompareExchange(ref _maxConcurrentSignatures, signing, max);
				}

				OnSign?.Invoke();
				return _key.SignHash(hash, hashAlgorithm, padding);
			}
			finally
			{
				Interlocked.Decrement(ref _signing);
			}
		}

		public override bool VerifyHash(byte[] hash, byte[] signature, HashAlgorithmName hashAlgorithm, RSASignaturePadding padding)
		{
			throw new NotSupportedException();
		}

		protected override void Dispose(bool disposing)
		{
			if (disposing)
			{
				Volatile.Write(ref _disposedWhileSigning, Volatile.Read(ref _signing) > 0);
				Volatile.Write(ref _isDisposed, true);
				_key.Dispose();
			}

			base.Dispose(disposing);
		}
	}

	// A platform key whose signatures a test controls, as a device's may differ: one that refuses RSASSA-PSS or makes it with the largest salt, or one whose signatures are corrupt. It counts the
	// signatures that it is asked for. Without a private exponent, it only reports its public key.
	private sealed class TestRsa : RSA
	{
		private readonly RSAParameters _parameters;
		private readonly PssBehavior _pss;
		private readonly bool _corrupt;
		private readonly RSA? _key;

		public TestRsa(RSAParameters parameters, PssBehavior pss = PssBehavior.Sign, bool corrupt = false)
		{
			_parameters = parameters;
			_pss = pss;
			_corrupt = corrupt;
			_key = parameters.D is null ? null : Create(parameters);
		}

		public int PssRequests { get; private set; }

		public int Pkcs1Requests { get; private set; }

		public bool IsDisposed { get; private set; }

		public override RSAParameters ExportParameters(bool includePrivateParameters)
		{
			return includePrivateParameters ? throw new CryptographicException("The key is not exportable.") : new RSAParameters { Modulus = _parameters.Modulus, Exponent = _parameters.Exponent };
		}

		public override void ImportParameters(RSAParameters parameters)
		{
			throw new NotSupportedException();
		}

		public override byte[] SignHash(byte[] hash, HashAlgorithmName hashAlgorithm, RSASignaturePadding padding)
		{
			RSA key = _key ?? throw new CryptographicException("The key has no private key.");
			byte[] signature;

			if (padding == RSASignaturePadding.Pss)
			{
				++PssRequests;
				int modulusBits = (int)new BigInteger(_parameters.Modulus, true, true).GetBitLength();

				signature = _pss switch
				{
					PssBehavior.Refuse => throw new CryptographicException("The device does not make RSASSA-PSS signatures."),
					PssBehavior.MaximumSalt => RawSign(_parameters, EncodePss(modulusBits, hashAlgorithm, hash, (modulusBits + 6) / 8 - hash.Length - 2)),
					_ => key.SignHash(hash, hashAlgorithm, padding)
				};
			}
			else
			{
				++Pkcs1Requests;
				signature = key.SignHash(hash, hashAlgorithm, padding);
			}

			if (_corrupt)
			{
				signature[^1] ^= 1;
			}

			return signature;
		}

		public override bool VerifyHash(byte[] hash, byte[] signature, HashAlgorithmName hashAlgorithm, RSASignaturePadding padding)
		{
			throw new NotSupportedException();
		}

		protected override void Dispose(bool disposing)
		{
			if (disposing)
			{
				IsDisposed = true;
				_key?.Dispose();
			}

			base.Dispose(disposing);
		}
	}
}
