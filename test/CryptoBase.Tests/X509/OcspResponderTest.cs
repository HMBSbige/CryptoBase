using CryptoBase.Abstractions.Signatures;
using CryptoBase.Signatures;
using CryptoBase.Signatures.Ecdsa;
using CryptoBase.X509;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using static CryptoBase.Tests.TestUtils;
using static CryptoBase.Tests.X509.TestCrl;
using static CryptoBase.Tests.X509.TestOcsp;
using static CryptoBase.Tests.X509.X509TestUtils;

namespace CryptoBase.Tests.X509;

// OcspResponse.Basic.FindResponder: the authorized responder that signed a response (RFC 6960, Sec. 4.2.2.2), whatever the time.
public class OcspResponderTest
{
	private static readonly Certificate CA = Certificate.DecodePem(OcspVectors.CA);
	private static readonly Certificate VectorResponder = Certificate.DecodePem(OcspVectors.Responder);

	private static OcspResponse.Basic Vector(string response)
	{
		return OcspResponse.Decode(Convert.FromBase64String(response)) as OcspResponse.Basic ?? throw new InvalidOperationException("The vector is not of the basic type.");
	}

	// A response for a leaf of the authority, from the responder that ResponderId names, with the certificates given.
	private static Basic ResponseFor(TestPki.Authority authority, byte[] responderId, params Certificate[] certificates)
	{
		Certificate leaf = authority.IssueLeaf();
		return new Basic { ResponderId = responderId, Responses = [new SingleEntry { CertificateId = CertificateIdOf(leaf, authority.Certificate) }.Encode()], Certificates = certificates.Length is 0 ? null : [.. certificates.Select(static certificate => certificate.Encoded.ToArray())] };
	}

	private static TestPki.Template ResponderTemplate(ISignatureKey key)
	{
		return new TestPki.Template { Subject = Name("CN=Delegated Responder"), SubjectPublicKeyInfo = Signatures.SignatureTestUtils.ExportSubjectPublicKeyInfo(key), Extensions = [TestPki.ExtendedKeyUsage(OcspSigningOid)] };
	}

	private static async Task AssertNoResponderAsync(OcspResponse.Basic response, Certificate issuer, string? expected = null)
	{
		Certificate? responder = response.FindResponder(issuer, SignatureKey.ImportSubjectPublicKeyInfo, out string? problem);

		await Assert.That(responder).IsNull();
		await Assert.That(problem).IsNotNull().And.IsNotEmpty();

		if (expected is not null)
		{
			await Assert.That(problem).Contains(expected);
		}
	}

	// The responses of OpenSSL, signed by the CA by name and by key hash, and by a delegated responder by name and by key hash.
	[Test]
	public async Task OpenSslResponsesHaveTheirResponders()
	{
		using (Assert.Multiple())
		{
			foreach (string vector in (string[])[OcspVectors.ResponseIssuerByName, OcspVectors.ResponseIssuerByKey])
			{
				await Assert.That(Vector(vector).FindResponder(CA, SignatureKey.ImportSubjectPublicKeyInfo, out string? problem)).IsSameReferenceAs(CA);
				await Assert.That(problem).IsNull();
			}

			foreach (string vector in (string[])[OcspVectors.ResponseDelegateByName, OcspVectors.ResponseDelegateByKey, OcspVectors.ResponseDelegateExtraCertificates])
			{
				OcspResponse.Basic response = Vector(vector);
				Certificate? responder = response.FindResponder(CA, SignatureKey.ImportSubjectPublicKeyInfo, out string? problem);
				await Assert.That(responder?.Encoded.ToArray()).IsEquivalentTo(VectorResponder.Encoded.ToArray(), CollectionOrdering.Matching);
				await Assert.That(response.Certificates.Any(certificate => ReferenceEquals(certificate, responder))).IsTrue();
				await Assert.That(problem).IsNull();
			}

			await AssertNoResponderAsync(Vector(OcspVectors.ResponseResponderWithoutEku), CA, "id-kp-OCSPSigning");
			await AssertNoResponderAsync(Vector(OcspVectors.ResponseForeignResponder), CA, "not issued by the CA");
			await AssertNoResponderAsync(Vector(OcspVectors.ResponseWithoutCertificates), CA);
		}
	}

	[Test]
	public async Task TheIssuerIsReturnedIfItSigned()
	{
		using TestPki.Authority authority = TestPki.Authority.CreateRoot("CN=OCSP CA");
		Basic byName = ResponseFor(authority, ResponderByName(authority.Name));
		Basic byKey = byName with { ResponderId = ResponderByKey(authority.Certificate) };
		Basic byNameInAnotherForm = byName with { ResponderId = ResponderByName(CommonName(Utf8StringTag, "ocsp  ca ")) };

		using (Assert.Multiple())
		{
			foreach (Basic basic in (Basic[])[byName, byKey, byNameInAnotherForm])
			{
				await Assert.That(basic.Decode(authority.Key).FindResponder(authority.Certificate, SignatureKey.ImportSubjectPublicKeyInfo, out string? problem)).IsSameReferenceAs(authority.Certificate);
				await Assert.That(problem).IsNull();
			}
		}
	}

	[Test]
	public async Task ADelegatedResponderIsReturnedIfItSigned()
	{
		using TestPki.Authority authority = TestPki.Authority.CreateRoot("CN=OCSP CA");
		using EcdsaP256 responderKey = EcdsaP256.GenerateKey();
		Certificate delegated = authority.Issue(ResponderTemplate(responderKey));
		Basic byKey = ResponseFor(authority, ResponderByKey(delegated), delegated);
		Basic byName = byKey with { ResponderId = ResponderByName(Name("CN=Delegated Responder")) };

		using (Assert.Multiple())
		{
			foreach (Basic basic in (Basic[])[byKey, byName])
			{
				OcspResponse.Basic response = basic.Decode(responderKey);
				await Assert.That(response.FindResponder(authority.Certificate, SignatureKey.ImportSubjectPublicKeyInfo, out string? problem)).IsSameReferenceAs(response.Certificates.Single());
				await Assert.That(problem).IsNull();
			}
		}
	}

	// RFC 6960, Sec. 4.2.2.2: a byName ResponderID does not tell a delegated responder with the CA's name from the CA, whose key is tried first.
	[Test]
	public async Task ADelegatedResponderMayHaveTheNameOfTheCa()
	{
		using TestPki.Authority authority = TestPki.Authority.CreateRoot("CN=OCSP CA");
		using EcdsaP256 responderKey = EcdsaP256.GenerateKey();
		Certificate delegated = authority.Issue(ResponderTemplate(responderKey) with { Subject = authority.Name });
		Basic basic = ResponseFor(authority, ResponderByName(authority.Name), delegated);
		OcspResponse.Basic fromDelegated = basic.Decode(responderKey);

		using (Assert.Multiple())
		{
			await Assert.That(fromDelegated.FindResponder(authority.Certificate, SignatureKey.ImportSubjectPublicKeyInfo, out _)).IsSameReferenceAs(fromDelegated.Certificates.Single());
			await Assert.That(basic.Decode(authority.Key).FindResponder(authority.Certificate, SignatureKey.ImportSubjectPublicKeyInfo, out _)).IsSameReferenceAs(authority.Certificate);
		}
	}

	// Each rule of Sec. 4.2.2.2 and of the policy that a delegated responder must pass, and the signature of the response.
	[Test]
	public async Task UnauthorizedSignersAreNotResponders()
	{
		using TestPki.Authority authority = TestPki.Authority.CreateRoot("CN=OCSP CA");
		using TestPki.Authority other = TestPki.Authority.CreateRoot("CN=Other CA");
		using EcdsaP256 responderKey = EcdsaP256.GenerateKey();
		using EcdsaP256 otherKey = EcdsaP256.GenerateKey();
		using RSA weakRsa = CreateRsa(1024);
		TestPki.Template template = ResponderTemplate(responderKey);
		Certificate valid = authority.Issue(template);
		Certificate noEku = authority.Issue(template with { Extensions = [] });
		Certificate noSignatureUsage = authority.Issue(template with { Extensions = [.. template.Extensions, TestPki.KeyUsage(X509KeyUsageFlags.KeyEncipherment)] });
		Certificate byOtherAuthority = other.Issue(template);
		Certificate unknownCritical = authority.Issue(template with { Extensions = [.. template.Extensions, new CertificateExtension(PrivateOid, true, NullValue)] });
		Certificate weakKey = authority.Issue(template with { SubjectPublicKeyInfo = weakRsa.ExportSubjectPublicKeyInfo() });
		Certificate signedWithSha1 = TestPki.Sign(template, authority.Name, Sequence(Oid("1.2.840.10045.4.1")), static _ => new byte[64]);
		Certificate wrongSignature = Certificate.Decode(WithCorruptedSignature(valid));

		OcspResponse.Basic Delegated(Certificate responder, ISignatureKey? signWith = null)
		{
			return ResponseFor(authority, ResponderByKey(responder), responder).Decode(signWith ?? responderKey);
		}

		using (Assert.Multiple())
		{
			await AssertNoResponderAsync(Delegated(noEku), authority.Certificate, "The responder's certificate does not assert id-kp-OCSPSigning.");
			await AssertNoResponderAsync(Delegated(noSignatureUsage), authority.Certificate, "digitalSignature");
			await AssertNoResponderAsync(Delegated(byOtherAuthority), authority.Certificate, "The responder's certificate is not issued by the CA that issued the certificate.");
			await AssertNoResponderAsync(Delegated(unknownCritical), authority.Certificate, $"The responder's certificate has the critical extension {PrivateOid}, which the checker does not process.");
			await AssertNoResponderAsync(Delegated(weakKey), authority.Certificate, "RSA key of 1024 bits");
			await AssertNoResponderAsync(Delegated(signedWithSha1), authority.Certificate, "which the policy refuses or does not support");
			await AssertNoResponderAsync(Delegated(wrongSignature), authority.Certificate, "The responder's certificate's signature does not verify with the issuer's key.");

			// The response's signature, by the delegated responder and by the CA.
			await AssertNoResponderAsync(Delegated(valid, otherKey), authority.Certificate, "The response's signature does not verify with the responder's key.");
			await AssertNoResponderAsync((ResponseFor(authority, ResponderByName(authority.Name)) with { Signature = new byte[64] }).Decode(authority.Key), authority.Certificate, "The response's signature does not verify with the issuer's key.");
			await AssertNoResponderAsync(ResponseFor(authority, ResponderByName(authority.Name)).Decode(otherKey), authority.Certificate);

			// A responder that is neither the CA nor a certificate of the response.
			await AssertNoResponderAsync(ResponseFor(authority, ResponderByKey(new byte[20]), valid).Decode(responderKey), authority.Certificate, "neither the certificate's issuer nor a certificate in the response");
			await AssertNoResponderAsync(ResponseFor(authority, ResponderByKey(valid)).Decode(responderKey), authority.Certificate);
		}
	}

	// RFC 6960, Sec. 4.3 allows SHA-1 responses, which the policy refuses.
	[Test]
	public async Task AResponseSignedWithAnAlgorithmThatThePolicyRefusesHasNoResponder()
	{
		using TestPki.Authority authority = TestPki.Authority.CreateRoot("CN=OCSP CA");
		Basic basic = ResponseFor(authority, ResponderByName(authority.Name)) with { Signature = new byte[64] };

		using (Assert.Multiple())
		{
			await AssertNoResponderAsync((basic with { SignatureAlgorithm = Sequence(Oid("1.2.840.113549.1.1.5"), [0x05, 0x00]) }).Decode(authority.Key), authority.Certificate, "which the policy refuses");
			await AssertNoResponderAsync((basic with { SignatureAlgorithm = Sequence(Oid("1.2.3.4")) }).Decode(authority.Key), authority.Certificate, "which is not supported");
		}
	}

	[Test]
	public async Task ManyCandidatesAreBounded()
	{
		using TestPki.Authority authority = TestPki.Authority.CreateRoot("CN=OCSP CA");
		using EcdsaP256 responderKey = EcdsaP256.GenerateKey();
		TestPki.Template template = ResponderTemplate(responderKey);
		Certificate noEku = authority.Issue(template with { Extensions = [] });
		Certificate valid = authority.Issue(template);
		Basic tooMany = ResponseFor(authority, ResponderByName(template.Subject), [.. Enumerable.Repeat(noEku, 8), valid]);
		Basic enough = ResponseFor(authority, ResponderByName(template.Subject), [.. Enumerable.Repeat(noEku, 7), valid]);
		OcspResponse.Basic enoughResponse = enough.Decode(responderKey);

		using (Assert.Multiple())
		{
			await AssertNoResponderAsync(tooMany.Decode(responderKey), authority.Certificate, "The response names more than 8 certificates as its responder.");
			await Assert.That(enoughResponse.FindResponder(authority.Certificate, SignatureKey.ImportSubjectPublicKeyInfo, out _)).IsSameReferenceAs(enoughResponse.Certificates[^1]);
		}
	}

	// No time is checked: a delegated responder that is not valid now is still the responder, which CheckOcsp, as the validator, refuses now.
	// The times of the response do not matter either.
	[Test]
	public async Task TimesAreNotChecked()
	{
		using TestPki.Authority authority = TestPki.Authority.CreateRoot("CN=OCSP CA");
		using EcdsaP256 responderKey = EcdsaP256.GenerateKey();
		Certificate leaf = authority.IssueLeaf();
		byte[] certificateId = CertificateIdOf(leaf, authority.Certificate);
		TestPki.Template template = ResponderTemplate(responderKey);
		Certificate expired = authority.Issue(template with { NotBefore = Now.AddDays(-30), NotAfter = Now.AddDays(-1) });
		Certificate future = authority.Issue(template with { NotBefore = Now.AddDays(1), NotAfter = Now.AddDays(30) });
		SingleEntry stale = new() { CertificateId = certificateId, ThisUpdate = Time(Now.AddDays(-3), generalized: true), NextUpdate = Time(Now.AddDays(-2), generalized: true) };

		using (Assert.Multiple())
		{
			foreach (Certificate delegated in (Certificate[])[expired, future])
			{
				OcspResponse.Basic response = new Basic { ResponderId = ResponderByKey(delegated), Responses = [new SingleEntry { CertificateId = certificateId }.Encode()], Certificates = [delegated.Encoded.ToArray()] }.Decode(responderKey);
				RevocationResult checkedNow = RevocationChecker.CheckOcsp(response, leaf, authority.Certificate, SignatureKey.ImportSubjectPublicKeyInfo, Now);

				await Assert.That(response.FindResponder(authority.Certificate, SignatureKey.ImportSubjectPublicKeyInfo, out string? problem)).IsSameReferenceAs(response.Certificates.Single());
				await Assert.That(problem).IsNull();
				await Assert.That(checkedNow.Status).IsEqualTo(RevocationStatus.Invalid);
				await Assert.That(checkedNow.Detail).IsEqualTo("The responder's certificate is not valid at the time.");
			}

			OcspResponse.Basic staleResponse = new Basic { ResponderId = ResponderByName(authority.Name), Responses = [stale.Encode()] }.Decode(authority.Key);
			await Assert.That(staleResponse.FindResponder(authority.Certificate, SignatureKey.ImportSubjectPublicKeyInfo, out _)).IsSameReferenceAs(authority.Certificate);
		}
	}

	// The importer is called as the validator calls it: a key that it does not support or finds invalid is a problem, and a null key throws.
	[Test]
	public async Task TheImporterIsUsedAsByTheValidator()
	{
		using TestPki.Authority authority = TestPki.Authority.CreateRoot("CN=OCSP CA");
		OcspResponse.Basic response = ResponseFor(authority, ResponderByName(authority.Name)).Decode(authority.Key);

		using (Assert.Multiple())
		{
			await Assert.That(response.FindResponder(authority.Certificate, static _ => throw new NotSupportedException("Not supported."), out string? unsupported)).IsNull();
			await Assert.That(unsupported).IsEqualTo("The issuer's key cannot be imported: Not supported.");
			await Assert.That(response.FindResponder(authority.Certificate, static _ => throw new CryptographicException("Invalid."), out string? invalid)).IsNull();
			await Assert.That(invalid).IsEqualTo("The issuer's key cannot be imported: Invalid.");
			await Assert.That(() => response.FindResponder(authority.Certificate, static _ => null!, out _)).Throws<InvalidOperationException>();
			await Assert.That(() => response.FindResponder(authority.Certificate, static _ => throw new TimeoutException(), out _)).Throws<TimeoutException>();
		}
	}

	// Every key that the method imports is disposed, whichever way it returns: the issuer's, and each candidate's, whether it signed or not, and when the importer throws for a candidate.
	[Test]
	public async Task DisposesEveryKeyThatItImports()
	{
		using TestPki.Authority authority = TestPki.Authority.CreateRoot("CN=OCSP CA");
		using EcdsaP256 responderKey = EcdsaP256.GenerateKey();
		using EcdsaP256 otherKey = EcdsaP256.GenerateKey();
		TestPki.Template template = ResponderTemplate(responderKey);
		Certificate valid = authority.Issue(template);
		Certificate noEku = authority.Issue(template with { Extensions = [] });
		Certificate wrongSignature = Certificate.Decode(WithCorruptedSignature(valid));
		byte[] responderKeyInfo = valid.PublicKeyInfo.Encoded.ToArray();

		(string Name, OcspResponse.Basic Response, bool Found, int Imports)[] cases =
		[
			("signed by the issuer", ResponseFor(authority, ResponderByName(authority.Name)).Decode(authority.Key), true, 1),
			("signed by a delegated responder", ResponseFor(authority, ResponderByKey(valid), valid).Decode(responderKey), true, 2),
			("a response signature that does not verify with the issuer's key", ResponseFor(authority, ResponderByName(authority.Name)).Decode(otherKey), false, 1),
			("a response signature that does not verify with the responder's key", ResponseFor(authority, ResponderByKey(valid), valid).Decode(otherKey), false, 2),
			("a responder's certificate whose signature does not verify", ResponseFor(authority, ResponderByKey(valid), wrongSignature).Decode(responderKey), false, 2),
			("a responder's certificate without id-kp-OCSPSigning", ResponseFor(authority, ResponderByKey(noEku), noEku).Decode(responderKey), false, 1),
			("too many candidates", ResponseFor(authority, ResponderByName(template.Subject), [.. Enumerable.Repeat(noEku, 8), valid]).Decode(responderKey), false, 1),
			("an algorithm that the policy refuses", (ResponseFor(authority, ResponderByName(authority.Name)) with { SignatureAlgorithm = Sequence(Oid("1.2.840.113549.1.1.5"), [0x05, 0x00]), Signature = new byte[64] }).Decode(authority.Key), false, 0)
		];

		using (Assert.Multiple())
		{
			foreach ((string name, OcspResponse.Basic response, bool found, int imports) in cases)
			{
				KeyLog log = new();
				Certificate? responder = response.FindResponder(authority.Certificate, log.Import, out _);

				await Assert.That(responder is not null).IsEqualTo(found).Because(name);
				await Assert.That(log.Imports).IsEqualTo(imports).Because(name);
				await Assert.That(log.Disposals).IsEqualTo(log.Imports).Because(name);
			}

			// The importer throws for the delegated responder's key, after it imported the issuer's.
			KeyLog throwing = new();
			OcspResponse.Basic delegated = ResponseFor(authority, ResponderByKey(valid), valid).Decode(responderKey);
			await Assert.That(() => delegated.FindResponder(authority.Certificate, subjectPublicKeyInfo => subjectPublicKeyInfo.SequenceEqual(responderKeyInfo) ? throw new TimeoutException() : throwing.Import(subjectPublicKeyInfo), out _)).Throws<TimeoutException>();
			await Assert.That(throwing.Imports).IsEqualTo(1);
			await Assert.That(throwing.Disposals).IsEqualTo(1);
		}
	}

	[Test]
	public async Task NullArgumentsThrow()
	{
		using TestPki.Authority authority = TestPki.Authority.CreateRoot("CN=OCSP CA");
		OcspResponse.Basic response = ResponseFor(authority, ResponderByName(authority.Name)).Decode(authority.Key);

		using (Assert.Multiple())
		{
			await Assert.That(() => response.FindResponder(null!, SignatureKey.ImportSubjectPublicKeyInfo, out _)).Throws<ArgumentNullException>().WithParameterName("issuer");
			await Assert.That(() => response.FindResponder(authority.Certificate, null!, out _)).Throws<ArgumentNullException>().WithParameterName("importPublicKey");
		}
	}

	private static byte[] WithCorruptedSignature(Certificate certificate)
	{
		byte[] encoded = certificate.Encoded.ToArray();
		encoded[^1] ^= 0x01;
		return encoded;
	}
}
