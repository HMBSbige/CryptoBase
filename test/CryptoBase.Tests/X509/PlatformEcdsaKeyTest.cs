using CryptoBase.Abstractions.Signatures;
using CryptoBase.Signatures;
using CryptoBase.Signatures.MLDsa;
using CryptoBase.Tests.Signatures;
using CryptoBase.Tests.Signatures.Ecdsa;
using CryptoBase.X509;
using System.Diagnostics.CodeAnalysis;
using System.Formats.Asn1;
using System.Security.Cryptography;
using static CryptoBase.Tests.Signatures.SignatureTestUtils;
using static CryptoBase.Tests.TestUtils;

namespace CryptoBase.Tests.X509;

[SuppressMessage("ReSharper", "AccessToDisposedClosure")]
public class PlatformEcdsaKeyTest
{
	[Test]
	[MatrixDataSource]
	public async Task SignsThroughThePlatformAndVerifiesLikeCryptoBase([Matrix(256, 384, 521)] int curveBits)
	{
		ECDsa platform = ECDsa.Create(EcdsaCurve(curveBits).Curve);
		byte[] subjectPublicKeyInfo = platform.ExportSubjectPublicKeyInfo();
		using ECDsa verifier = ECDsa.Create();
		verifier.ImportSubjectPublicKeyInfo(subjectPublicKeyInfo, out _);
		using PlatformEcdsaKey key = new(platform);
		using ISignatureKey cryptoBase = SignatureKey.ImportSubjectPublicKeyInfo(subjectPublicKeyInfo);
		byte[] exported = ExportSubjectPublicKeyInfo(key);
		byte[] message = CreateDeterministicSource(100);

		using (Assert.Multiple())
		{
			await Assert.That(key.HasPrivateKey).IsTrue();
			await Assert.That(exported).IsEquivalentTo(subjectPublicKeyInfo, CollectionOrdering.Matching);

			foreach (SignatureAlgorithm algorithm in Enum.GetValues<SignatureAlgorithm>())
			{
				await Assert.That(key.Supports(algorithm)).IsEqualTo(cryptoBase.Supports(algorithm)).Because(algorithm.ToString());
			}

			foreach (SignatureAlgorithm algorithm in EcdsaTestUtils.Algorithms)
			{
				byte[] signatureOutput = CreateGuardedBuffer(1, key.GetMaxSignatureLength(algorithm));
				int written = key.Sign(algorithm, message, signatureOutput.AsSpan(1));
				byte[] signature = signatureOutput.AsSpan(1, written).ToArray();

				await Assert.That(key.GetMaxSignatureLength(algorithm)).IsEqualTo(cryptoBase.GetMaxSignatureLength(algorithm));
				await AssertOutput(signatureOutput, 1, signature);
				await Assert.That(cryptoBase.Verify(algorithm, message, signature)).IsTrue();
				await Assert.That(verifier.VerifyData(message, signature, EcdsaTestUtils.HashName(algorithm), DSASignatureFormat.Rfc3279DerSequence)).IsTrue();
				await Assert.That(key.Verify(algorithm, message, signature)).IsTrue();
				await Assert.That(key.Verify(algorithm, Flip(message, 0), signature)).IsFalse();
				await Assert.That(key.Verify(algorithm, message, Flip(signature, signature.Length - 1))).IsFalse();
			}
		}
	}

	// The platform alone also accepts an INTEGER without the zero byte that its sign needs; DER and CryptoBase do not.
	[Test]
	public async Task VerifiesOnlyStrictDerLikeCryptoBase()
	{
		using PlatformEcdsaKey key = new(ECDsa.Create(ECCurve.NamedCurves.nistP256));
		using ISignatureKey cryptoBase = SignatureKey.ImportSubjectPublicKeyInfo(ExportSubjectPublicKeyInfo(key));
		byte[] message = [1, 2, 3];
		byte[] r, s;

		// A signature whose r needs the zero byte for its sign and whose s does not.
		do
		{
			AsnReader sequence = new AsnReader(Sign(key, SignatureAlgorithm.EcdsaSha256, message), AsnEncodingRules.DER).ReadSequence();
			r = sequence.ReadIntegerBytes().ToArray();
			s = sequence.ReadIntegerBytes().ToArray();
		}
		while (r.Length != 33 || s.Length != 32 || s[0] is 0);

		byte[] integers = [.. Tlv(0x02, r), .. Tlv(0x02, s)];
		(string Case, byte[] Signature)[] invalid =
		[
			("negative r", Sequence(Tlv(0x02, r.AsSpan(1).ToArray()), Tlv(0x02, s))),
			("redundant zero byte", Sequence(Tlv(0x02, r), Tlv(0x02, [0x00, .. s]))),
			("r longer than the field", Sequence(Tlv(0x02, [0x01, .. r.AsSpan(1)]), Tlv(0x02, s))),
			("long-form length", [0x30, 0x81, (byte)integers.Length, .. integers]),
			("trailing byte", [.. Sequence(integers), 0x00]),
			("IEEE P1363", [.. r.AsSpan(1), .. s]),
		];

		using (Assert.Multiple())
		{
			await Assert.That(key.Verify(SignatureAlgorithm.EcdsaSha256, message, Sequence(integers))).IsTrue();

			foreach ((string @case, byte[] signature) in invalid)
			{
				await Assert.That(key.Verify(SignatureAlgorithm.EcdsaSha256, message, signature)).IsFalse().Because(@case);
				await Assert.That(cryptoBase.Verify(SignatureAlgorithm.EcdsaSha256, message, signature)).IsFalse().Because(@case);
			}
		}
	}

	[Test]
	public async Task NeverExportsThePrivateKey()
	{
		using PlatformEcdsaKey key = new(ECDsa.Create(ECCurve.NamedCurves.nistP256));
		byte[] destination = CreateGuardedBuffer(0, 200);

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
		using PlatformEcdsaKey key = new(ECDsa.Create(ECCurve.NamedCurves.nistP256));
		byte[] signature = CreateGuardedBuffer(0, 100);
		byte[] message = [1, 2, 3];

		using (Assert.Multiple())
		{
			foreach (SignatureAlgorithm algorithm in (SignatureAlgorithm[])[SignatureAlgorithm.MLDsa44, SignatureAlgorithm.RsaPssSha256, 0])
			{
				await Assert.That(() => key.Sign(algorithm, message, signature)).Throws<ArgumentException>().WithParameterName("algorithm");
				await Assert.That(() => key.Verify(algorithm, message, signature)).Throws<ArgumentException>().WithParameterName("algorithm");
				await Assert.That(() => key.GetMaxSignatureLength(algorithm)).Throws<ArgumentException>().WithParameterName("algorithm");
			}

			foreach (int shortfall in (int[])[1, int.MaxValue])
			{
				byte[] shortSignature = ShortBuffer(key.GetMaxSignatureLength(SignatureAlgorithm.EcdsaSha256), shortfall);
				byte[] shortSubjectPublicKeyInfo = ShortBuffer(key.SubjectPublicKeyInfoLength, shortfall);

				await Assert.That(() => key.Sign(SignatureAlgorithm.EcdsaSha256, message, shortSignature)).Throws<ArgumentException>().WithParameterName("destination");
				await Assert.That(() => key.ExportSubjectPublicKeyInfo(shortSubjectPublicKeyInfo)).Throws<ArgumentException>().WithParameterName("destination");
				await Assert.That(shortSignature).All(static value => value is DestinationSentinel);
				await Assert.That(shortSubjectPublicKeyInfo).All(static value => value is DestinationSentinel);
			}

			await Assert.That(signature).All(static value => value is DestinationSentinel);
			await Assert.That(() => new PlatformEcdsaKey(null!)).ThrowsExactly<ArgumentNullException>();
		}
	}

	// SignatureKey supports this key, unlike PlatformEcdsaKey.
	public static IEnumerable<Func<(string Case, byte[] SubjectPublicKeyInfo)>> MLDsaPublicKeys()
	{
		yield return static () =>
		{
			using MLDsa44 key = MLDsa44.GenerateKey();
			return ("ML-DSA-44", ExportSubjectPublicKeyInfo(key));
		};
	}

	// The SubjectPublicKeyInfo of the platform key decides, so a test double reports keys that the platform need not support.
	[Test]
	[MethodDataSource(typeof(SignatureKeyTest), nameof(SignatureKeyTest.UnsupportedPublicKeys))]
	[MethodDataSource(nameof(MLDsaPublicKeys))]
	public async Task OtherKeysAreNotSupported(string @case, byte[] subjectPublicKeyInfo)
	{
		using TestEcdsa other = new(subjectPublicKeyInfo);

		using (Assert.Multiple())
		{
			await Assert.That(() => new PlatformEcdsaKey(other)).ThrowsExactly<NotSupportedException>().Because(@case);

			// The caller still owns the key.
			await Assert.That(other.IsDisposed).IsFalse();
		}
	}

	[Test]
	public async Task DisposeAlsoDisposesThePlatformKey()
	{
		ECDsa platform = ECDsa.Create(ECCurve.NamedCurves.nistP256);
		PlatformEcdsaKey key = new(platform);
		byte[] message = [1, 2, 3];
		byte[] signature = new byte[key.GetMaxSignatureLength(SignatureAlgorithm.EcdsaSha256)];
		int written = key.Sign(SignatureAlgorithm.EcdsaSha256, message, signature);
		key.Dispose();
		key.Dispose();

		using (Assert.Multiple())
		{
			await Assert.That(() => key.HasPrivateKey).ThrowsExactly<ObjectDisposedException>();
			await Assert.That(() => key.SubjectPublicKeyInfoLength).ThrowsExactly<ObjectDisposedException>();
			await Assert.That(() => key.Pkcs8PrivateKeyLength).ThrowsExactly<ObjectDisposedException>();
			await Assert.That(() => key.Supports(SignatureAlgorithm.EcdsaSha256)).ThrowsExactly<ObjectDisposedException>();
			await Assert.That(() => key.GetMaxSignatureLength(SignatureAlgorithm.EcdsaSha256)).ThrowsExactly<ObjectDisposedException>();
			await Assert.That(() => key.Sign(SignatureAlgorithm.EcdsaSha256, message, signature)).ThrowsExactly<ObjectDisposedException>();
			await Assert.That(() => key.Verify(SignatureAlgorithm.EcdsaSha256, message, signature.AsSpan(0, written))).ThrowsExactly<ObjectDisposedException>();
			await Assert.That(() => key.ExportSubjectPublicKeyInfo(new byte[200])).ThrowsExactly<ObjectDisposedException>();
			await Assert.That(() => key.ExportPkcs8PrivateKey(new byte[200])).ThrowsExactly<ObjectDisposedException>();
			await Assert.That(() => platform.SignData(message, HashAlgorithmName.SHA256)).Throws<ObjectDisposedException>();
		}
	}

	[Test]
	public async Task SignsConcurrently()
	{
		using PlatformEcdsaKey key = new(ECDsa.Create(ECCurve.NamedCurves.nistP256));
		byte[] message = CreateDeterministicSource(64);

		bool[] verified = await Task.WhenAll(Enumerable.Range(0, 32).Select(_ => Task.Run(() => key.Verify(SignatureAlgorithm.EcdsaSha384, message, Sign(key, SignatureAlgorithm.EcdsaSha384, message)))));

		await Assert.That(verified).All(static value => value);
	}
}
