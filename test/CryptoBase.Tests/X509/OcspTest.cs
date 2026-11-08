using CryptoBase.Abstractions.Signatures;
using CryptoBase.Signatures;
using CryptoBase.Signatures.Ecdsa;
using CryptoBase.X509;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using static CryptoBase.Tests.TestUtils;
using static CryptoBase.Tests.X509.TestCrl;
using static CryptoBase.Tests.X509.TestOcsp;
using static CryptoBase.Tests.X509.X509TestUtils;

namespace CryptoBase.Tests.X509;

public class OcspTest
{
	// A time at which every certificate of the vectors is valid and every response current.
	private static readonly DateTimeOffset VectorTime = new(2026, 11, 8, 16, 50, 0, TimeSpan.Zero);

	private static readonly Certificate CA = Certificate.DecodePem(OcspVectors.CA);
	private static readonly Certificate GoodLeaf = Certificate.DecodePem(OcspVectors.Good);
	private static readonly Certificate RevokedLeaf = Certificate.DecodePem(OcspVectors.Revoked);
	private static readonly Certificate UnknownLeaf = Certificate.DecodePem(OcspVectors.Unknown);

	private static OcspResponse Vector(string response)
	{
		return OcspResponse.Decode(Convert.FromBase64String(response));
	}

	private static RevocationResult CheckVector(string response, Certificate certificate, DateTimeOffset? time = null)
	{
		return RevocationChecker.CheckOcsp(Vector(response), certificate, CA, SignatureKey.ImportSubjectPublicKeyInfo, time ?? VectorTime);
	}

	private static RevocationResult Check(OcspResponse response, Certificate certificate, TestPki.Authority authority, DateTimeOffset? time = null)
	{
		return RevocationChecker.CheckOcsp(response, certificate, authority.Certificate, SignatureKey.ImportSubjectPublicKeyInfo, time ?? Now);
	}

	private static async Task AssertStatusAsync(RevocationResult result, RevocationStatus expected)
	{
		await Assert.That(result.Status).IsEqualTo(expected).Because(result.Detail ?? "");
	}

	// The fields of a request, and its exact encoding.
	[Test]
	public async Task RequestsMatchOpenSsl()
	{
		byte[] nonce = [.. Enumerable.Range(0, 32).Select(static i => (byte)(0xA0 + i))];

		OcspRequest plain = OcspRequest.Create(GoodLeaf, CA, default, HashAlgorithmName.SHA1);
		OcspRequest withNonce = OcspRequest.Create(GoodLeaf, CA, nonce, HashAlgorithmName.SHA1);
		OcspRequest sha256 = OcspRequest.Create(GoodLeaf, CA, default, HashAlgorithmName.SHA256);
		OcspRequest byDefault = OcspRequest.Create(GoodLeaf, CA);

		using (Assert.Multiple())
		{
			await Assert.That(byDefault.Encoded.ToArray()).IsEquivalentTo(Convert.FromBase64String(OcspVectors.RequestSha256), CollectionOrdering.Matching);
			await Assert.That(plain.Encoded.ToArray()).IsEquivalentTo(Convert.FromBase64String(OcspVectors.RequestGood), CollectionOrdering.Matching);
			await Assert.That(withNonce.Encoded.ToArray()).IsEquivalentTo(Convert.FromBase64String(OcspVectors.RequestWithNonce), CollectionOrdering.Matching);
			await Assert.That(sha256.Encoded.ToArray()).IsEquivalentTo(Convert.FromBase64String(OcspVectors.RequestSha256), CollectionOrdering.Matching);
			await Assert.That(plain.Nonce).IsNull();
			await Assert.That(withNonce.Nonce?.ToArray()).IsEquivalentTo(nonce, CollectionOrdering.Matching);
			await Assert.That(plain.CertificateId.SerialNumber.ToArray()).IsEquivalentTo(GoodLeaf.SerialNumber.ToArray(), CollectionOrdering.Matching);
			await Assert.That(plain.CertificateId.HashAlgorithm.Oid).IsEqualTo("1.3.14.3.2.26");
			await Assert.That(sha256.CertificateId.HashAlgorithm.Oid).IsEqualTo("2.16.840.1.101.3.4.2.1");
			await Assert.That(plain.CertificateId.Matches(GoodLeaf, CA)).IsTrue();
			await Assert.That(sha256.CertificateId.Matches(GoodLeaf, CA)).IsTrue();
			await Assert.That(plain.CertificateId.Matches(RevokedLeaf, CA)).IsFalse();
		}
	}

	[Test]
	public async Task RequestsAcceptNoncesOfOneToThirtyTwoBytes()
	{
		using (Assert.Multiple())
		{
			await Assert.That(OcspRequest.Create(GoodLeaf, CA, new byte[1]).Nonce?.Length).IsEqualTo(1);
			await Assert.That(OcspRequest.Create(GoodLeaf, CA, new byte[32]).Nonce?.Length).IsEqualTo(32);
			await Assert.That(() => OcspRequest.Create(GoodLeaf, CA, new byte[33])).Throws<ArgumentException>();
			await Assert.That(() => OcspRequest.Create(GoodLeaf, CA, default, HashAlgorithmName.SHA384)).Throws<NotSupportedException>();
			await Assert.That(() => OcspRequest.Create(null!, CA)).Throws<ArgumentNullException>();
			await Assert.That(() => OcspRequest.Create(GoodLeaf, null!)).Throws<ArgumentNullException>();
		}
	}

	[Test]
	public async Task OpenSslResponsesDecode()
	{
		OcspResponse byName = Vector(OcspVectors.ResponseIssuerByName);
		OcspResponse byKey = Vector(OcspVectors.ResponseDelegateByKey);
		OcspResponse revoked = Vector(OcspVectors.ResponseRevoked);
		OcspResponse unknown = Vector(OcspVectors.ResponseUnknown);
		OcspSingleResponse single = byName.Responses.Single();
		OcspSingleResponse revokedSingle = revoked.Responses.Single();

		using (Assert.Multiple())
		{
			await Assert.That(byName.Status).IsEqualTo(OcspResponseStatus.Successful);
			await Assert.That(byName.ResponseType).IsEqualTo(BasicOid);
			await Assert.That(byName.Responder?.ByName?.ToArray()).IsEquivalentTo(CA.Subject.ToArray(), CollectionOrdering.Matching);
			await Assert.That(byName.Responder?.ByKey).IsNull();
			await Assert.That(byKey.Responder?.ByName).IsNull();
			await Assert.That(byKey.Responder?.ByKey?.Length).IsEqualTo(20);
			await Assert.That(byName.ProducedAt).IsNotNull();
			await Assert.That(byName.TbsResponseData.IsEmpty).IsFalse();
			await Assert.That(byName.Signature.IsEmpty).IsFalse();
			await Assert.That(byName.SignatureAlgorithm?.Oid).IsEqualTo("1.2.840.10045.4.3.2");
			await Assert.That(byName.Certificates.Single().Encoded.ToArray()).IsEquivalentTo(CA.Encoded.ToArray(), CollectionOrdering.Matching);
			await Assert.That(byKey.Certificates.Single().Subject.ToArray()).IsEquivalentTo(Certificate.DecodePem(OcspVectors.Responder).Subject.ToArray(), CollectionOrdering.Matching);
			await Assert.That(single.CertificateId.Matches(GoodLeaf, CA)).IsTrue();
			await Assert.That(single.Status).IsEqualTo(OcspCertificateStatus.Good);
			await Assert.That(single.NextUpdate).IsNotNull();
			await Assert.That(single.RevocationTime).IsNull();
			await Assert.That(revokedSingle.Status).IsEqualTo(OcspCertificateStatus.Revoked);
			await Assert.That(revokedSingle.RevocationTime).IsNotNull();
			await Assert.That(revokedSingle.RevocationReason).IsEqualTo(X509RevocationReason.KeyCompromise);
			await Assert.That(unknown.Responses.Single().Status).IsEqualTo(OcspCertificateStatus.Unknown);
		}
	}

	[Test]
	public async Task VerifySignatureUsesTheResponseData()
	{
		OcspResponse response = Vector(OcspVectors.ResponseIssuerByName);
		using ISignatureKey key = SignatureKey.ImportSubjectPublicKeyInfo(CA.PublicKeyInfo.Encoded.Span);
		using EcdsaP256 other = EcdsaP256.GenerateKey();

		using (Assert.Multiple())
		{
			await Assert.That(response.VerifySignature(key)).IsTrue();
			await Assert.That(response.VerifySignature(other)).IsFalse();
			await Assert.That(() => response.VerifySignature(null!)).Throws<ArgumentNullException>();
		}
	}

	[Test]
	public async Task OpenSslResponsesAreChecked()
	{
		RevocationResult byName = CheckVector(OcspVectors.ResponseIssuerByName, GoodLeaf);
		RevocationResult byKey = CheckVector(OcspVectors.ResponseIssuerByKey, GoodLeaf);
		RevocationResult delegateByName = CheckVector(OcspVectors.ResponseDelegateByName, GoodLeaf);
		RevocationResult delegateByKey = CheckVector(OcspVectors.ResponseDelegateByKey, GoodLeaf);
		RevocationResult extraCertificates = CheckVector(OcspVectors.ResponseDelegateExtraCertificates, GoodLeaf);
		RevocationResult revoked = CheckVector(OcspVectors.ResponseRevoked, RevokedLeaf);
		RevocationResult unknown = CheckVector(OcspVectors.ResponseUnknown, UnknownLeaf);

		using (Assert.Multiple())
		{
			await AssertStatusAsync(byName, RevocationStatus.Good);
			await AssertStatusAsync(byKey, RevocationStatus.Good);
			await AssertStatusAsync(delegateByName, RevocationStatus.Good);
			await AssertStatusAsync(delegateByKey, RevocationStatus.Good);
			await AssertStatusAsync(extraCertificates, RevocationStatus.Good);
			await AssertStatusAsync(revoked, RevocationStatus.Revoked);
			await Assert.That(revoked.Reason).IsEqualTo(X509RevocationReason.KeyCompromise);
			await Assert.That(revoked.RevocationTime).IsNotNull();
			await AssertStatusAsync(unknown, RevocationStatus.Unknown);
		}
	}

	[Test]
	public async Task ResponsesFromUnauthorizedSignersAreInvalid()
	{
		using (Assert.Multiple())
		{
			// RFC 6960, Sec. 4.2.2.2: without id-kp-OCSPSigning, and from a responder that another CA issued.
			await AssertStatusAsync(CheckVector(OcspVectors.ResponseResponderWithoutEku, GoodLeaf), RevocationStatus.Invalid);
			await AssertStatusAsync(CheckVector(OcspVectors.ResponseForeignResponder, GoodLeaf), RevocationStatus.Invalid);

			// The response's certificates are gone, so nothing names the responder's key.
			await AssertStatusAsync(CheckVector(OcspVectors.ResponseWithoutCertificates, GoodLeaf), RevocationStatus.Invalid);
		}
	}

	[Test]
	public async Task AResponseWithoutTheCertificateIsInvalid()
	{
		await AssertStatusAsync(CheckVector(OcspVectors.ResponseIssuerByName, RevokedLeaf), RevocationStatus.Invalid);
	}

	// RFC 9919, Sec. 5, and RFC 6960, Sec. 4.2.2.1: the validity interval, with the clock skew around it.
	[Test]
	public async Task TheValidityIntervalIsCheckedWithTheClockSkew()
	{
		OcspSingleResponse single = Vector(OcspVectors.ResponseShortValidity).Responses.Single();
		DateTimeOffset nextUpdate = single.NextUpdate ?? throw new InvalidOperationException();
		DateTimeOffset thisUpdate = single.ThisUpdate;
		TimeSpan skew = RevocationChecker.OcspClockSkew;

		using (Assert.Multiple())
		{
			await AssertStatusAsync(CheckVector(OcspVectors.ResponseShortValidity, GoodLeaf, nextUpdate), RevocationStatus.Good);
			await AssertStatusAsync(CheckVector(OcspVectors.ResponseShortValidity, GoodLeaf, nextUpdate + skew), RevocationStatus.Good);
			await AssertStatusAsync(CheckVector(OcspVectors.ResponseShortValidity, GoodLeaf, nextUpdate + skew + TimeSpan.FromSeconds(1)), RevocationStatus.Invalid);
			await AssertStatusAsync(CheckVector(OcspVectors.ResponseShortValidity, GoodLeaf, thisUpdate - skew), RevocationStatus.Good);
			await AssertStatusAsync(CheckVector(OcspVectors.ResponseShortValidity, GoodLeaf, thisUpdate - skew - TimeSpan.FromSeconds(1)), RevocationStatus.Invalid);
		}
	}

	// RFC 9919, Sec. 5: a client that sent no nonce ignores one in the response.
	[Test]
	public async Task ANonceInTheResponseIsIgnored()
	{
		await AssertStatusAsync(CheckVector(OcspVectors.ResponseWithNonce, GoodLeaf), RevocationStatus.Good);
	}

	[Test]
	[Arguments((byte)0x01, OcspResponseStatus.MalformedRequest)]
	[Arguments((byte)0x02, OcspResponseStatus.InternalError)]
	[Arguments((byte)0x03, OcspResponseStatus.TryLater)]
	[Arguments((byte)0x05, OcspResponseStatus.SignatureRequired)]
	[Arguments((byte)0x06, OcspResponseStatus.Unauthorized)]
	public async Task ErrorStatusesDecodeAndAreInvalid(byte status, OcspResponseStatus expected)
	{
		using EcdsaP256 key = EcdsaP256.GenerateKey();
		OcspResponse response = OcspResponse.Decode(Sequence([0x0A, 0x01, status]));

		using (Assert.Multiple())
		{
			await Assert.That(response.Status).IsEqualTo(expected);
			await Assert.That(response.ResponseType).IsNull();
			await Assert.That(response.Responses).IsEmpty();
			await Assert.That(response.Certificates).IsEmpty();
			await Assert.That(response.ProducedAt).IsNull();
			await Assert.That(response.Responder).IsNull();
			await Assert.That(response.SignatureAlgorithm).IsNull();
			await Assert.That(response.VerifySignature(key)).IsFalse();
			await AssertStatusAsync(RevocationChecker.CheckOcsp(response, GoodLeaf, CA, SignatureKey.ImportSubjectPublicKeyInfo, VectorTime), RevocationStatus.Invalid);
		}
	}

	[Test]
	public async Task MalformedResponsesAreRefused()
	{
		using EcdsaP256 key = EcdsaP256.GenerateKey();
		byte[] responderId = ResponderByName(Name("CN=Responder"));
		SingleEntry single = new() { CertificateId = CertificateIdOf(GoodLeaf, CA) };
		Basic basic = new() { ResponderId = responderId, Responses = [single.Encode()] };
		byte[] errorWithBytes = Sequence([0x0A, 0x01, 0x01], Tlv(0xA0, Sequence(Oid(BasicOid), Tlv(0x04, [0x05, 0x00]))));
		byte[] notUsedStatus = Sequence([0x0A, 0x01, 0x04]);
		byte[] undefinedStatus = Sequence([0x0A, 0x01, 0x07]);
		byte[] noBytes = Sequence([0x0A, 0x01, 0x00]);
		byte[] notBasic = Sequence([0x0A, 0x01, 0x00], Tlv(0xA0, Sequence(Oid(BasicOid), Tlv(0x04, Sequence()))));
		byte[] version = (basic with { Version = [0x02, 0x01, 0x00] }).Encode(key);
		byte[] trailing = [.. basic.Encode(key), 0x00];
		byte[] badTime = (basic with { ProducedAt = Time(Now) }).Encode(key);
		byte[] emptyExtensions = (basic with { Extensions = [] }).Encode(key);
		byte[] repeatedExtensions = (basic with { Extensions = [Nonce([0x01]), Nonce([0x02])] }).Encode(key);
		byte[] signatureWithUnusedBits = Successful(BasicOid, Sequence(basic.ResponseData(), EcdsaSha256, Tlv(0x03, [0x01, 0x02])));

		using (Assert.Multiple())
		{
			foreach (byte[] invalid in (byte[][])[errorWithBytes, notUsedStatus, undefinedStatus, noBytes, notBasic, version, trailing, badTime, emptyExtensions, repeatedExtensions, signatureWithUnusedBits, [], [0x30, 0x00]])
			{
				await Assert.That(() => OcspResponse.Decode(invalid)).Throws<ArgumentException>();
			}
		}
	}

	// A CertStatus or a reason with a value that is not defined.
	[Test]
	[SuppressMessage("ReSharper", "AccessToDisposedClosure", Justification = "Assertions are awaited before the key is disposed.")]
	public async Task SingleResponsesMustBeWellFormed()
	{
		using EcdsaP256 key = EcdsaP256.GenerateKey();
		byte[] certificateId = CertificateIdOf(GoodLeaf, CA);
		byte[] responderId = ResponderByName(Name("CN=Responder"));
		SingleEntry unknownTag = new() { CertificateId = certificateId, Status = [0x83, 0x00] };
		SingleEntry badReason = new() { CertificateId = certificateId, Status = Revoked(Now, 7) };
		SingleEntry utcThisUpdate = new() { CertificateId = certificateId, ThisUpdate = Time(Now) };

		using (Assert.Multiple())
		{
			foreach (SingleEntry single in (SingleEntry[])[unknownTag, badReason, utcThisUpdate])
			{
				await Assert.That(() => OcspResponse.Decode(new Basic { ResponderId = responderId, Responses = [single.Encode()] }.Encode(key))).Throws<ArgumentException>();
			}
		}
	}

	[Test]
	public async Task AnotherResponseTypeDecodesButIsInvalid()
	{
		OcspResponse response = OcspResponse.Decode(Successful("1.3.6.1.5.5.7.48.1.99", Sequence()));

		using (Assert.Multiple())
		{
			await Assert.That(response.ResponseType).IsEqualTo("1.3.6.1.5.5.7.48.1.99");
			await Assert.That(response.Responses).IsEmpty();
			await AssertStatusAsync(RevocationChecker.CheckOcsp(response, GoodLeaf, CA, SignatureKey.ImportSubjectPublicKeyInfo, VectorTime), RevocationStatus.Invalid);
		}
	}

	[Test]
	public async Task ResponsesFromTheCertificatesIssuerAreChecked()
	{
		using TestPki.Authority authority = TestPki.Authority.CreateRoot("CN=OCSP CA");
		Certificate leaf = authority.IssueLeaf();
		byte[] certificateId = CertificateIdOf(leaf, authority.Certificate);
		Basic response = new() { ResponderId = ResponderByName(authority.Name), Responses = [new SingleEntry { CertificateId = certificateId }.Encode()] };

		using (Assert.Multiple())
		{
			await AssertStatusAsync(Check(response.Decode(authority.Key), leaf, authority), RevocationStatus.Good);
			await AssertStatusAsync(Check((response with { ResponderId = ResponderByKey(authority.Certificate) }).Decode(authority.Key), leaf, authority), RevocationStatus.Good);
			await AssertStatusAsync(Check((response with { ResponderId = ResponderByKey(new byte[20]) }).Decode(authority.Key), leaf, authority), RevocationStatus.Invalid);
			await AssertStatusAsync(Check((response with { ResponderId = ResponderByName(Name("CN=Unknown")) }).Decode(authority.Key), leaf, authority), RevocationStatus.Invalid);

			// A wrong signature, and one by another key.
			await AssertStatusAsync(Check((response with { Signature = new byte[64] }).Decode(authority.Key), leaf, authority), RevocationStatus.Invalid);
			using EcdsaP256 other = EcdsaP256.GenerateKey();
			await AssertStatusAsync(Check(response.Decode(other), leaf, authority), RevocationStatus.Invalid);
		}
	}

	// RFC 6960, Sec. 4.3 allows SHA-1 responses, which the policy refuses like signatures in a certificate path.
	[Test]
	public async Task WeakSignaturesAreInvalid()
	{
		using TestPki.Authority authority = TestPki.Authority.CreateRoot("CN=OCSP CA");
		Certificate leaf = authority.IssueLeaf();
		byte[] certificateId = CertificateIdOf(leaf, authority.Certificate);
		byte[] sha1 = Sequence(Oid("1.2.840.113549.1.1.5"), [0x05, 0x00]);
		byte[] unknown = Sequence(Oid("1.2.3.4"));
		Basic response = new() { ResponderId = ResponderByName(authority.Name), Responses = [new SingleEntry { CertificateId = certificateId }.Encode()], Signature = new byte[64] };
		RevocationResult weak = Check((response with { SignatureAlgorithm = sha1 }).Decode(authority.Key), leaf, authority);
		RevocationResult unsupported = Check((response with { SignatureAlgorithm = unknown }).Decode(authority.Key), leaf, authority);

		using (Assert.Multiple())
		{
			await AssertStatusAsync(weak, RevocationStatus.Invalid);
			await Assert.That(weak.Detail).Contains("refuses");
			await AssertStatusAsync(unsupported, RevocationStatus.Invalid);
		}
	}

	[Test]
	public async Task ResponsesMustHaveANextUpdate()
	{
		using TestPki.Authority authority = TestPki.Authority.CreateRoot("CN=OCSP CA");
		Certificate leaf = authority.IssueLeaf();
		byte[] certificateId = CertificateIdOf(leaf, authority.Certificate);
		Basic response = new() { ResponderId = ResponderByName(authority.Name), Responses = [new SingleEntry { CertificateId = certificateId, NextUpdate = null }.Encode()] };

		await AssertStatusAsync(Check(response.Decode(authority.Key), leaf, authority), RevocationStatus.Invalid);
	}

	[Test]
	public async Task RevokedResponsesWithoutAReasonAreUnspecified()
	{
		using TestPki.Authority authority = TestPki.Authority.CreateRoot("CN=OCSP CA");
		Certificate leaf = authority.IssueLeaf();
		byte[] certificateId = CertificateIdOf(leaf, authority.Certificate);
		DateTimeOffset revocation = Now.AddDays(-1);
		RevocationResult result = Check(new Basic { ResponderId = ResponderByName(authority.Name), Responses = [new SingleEntry { CertificateId = certificateId, Status = Revoked(revocation) }.Encode()] }.Decode(authority.Key), leaf, authority);

		using (Assert.Multiple())
		{
			await AssertStatusAsync(result, RevocationStatus.Revoked);
			await Assert.That(result.Reason).IsEqualTo(X509RevocationReason.Unspecified);
			await Assert.That(result.RevocationTime).IsEqualTo(revocation);
		}
	}

	// Of several responses for the certificate, the most severe decides, and responses for other certificates are ignored.
	[Test]
	public async Task SeveralResponsesTakeTheMostSevere()
	{
		using TestPki.Authority authority = TestPki.Authority.CreateRoot("CN=OCSP CA");
		Certificate leaf = authority.IssueLeaf();
		Certificate other = authority.Issue(new TestPki.Template { SerialNumber = [0x02], Subject = Name("CN=Other"), SubjectPublicKeyInfo = leaf.PublicKeyInfo.Encoded.ToArray() });
		byte[] certificateId = CertificateIdOf(leaf, authority.Certificate);
		byte[] otherId = CertificateIdOf(other, authority.Certificate);
		byte[] good = new SingleEntry { CertificateId = certificateId }.Encode();
		byte[] revoked = new SingleEntry { CertificateId = certificateId, Status = Revoked(Now.AddDays(-1), 1) }.Encode();
		byte[] unknown = new SingleEntry { CertificateId = certificateId, Status = UnknownStatus }.Encode();

		using (Assert.Multiple())
		{
			await AssertStatusAsync(Check(new Basic { ResponderId = ResponderByName(authority.Name), Responses = [good, revoked] }.Decode(authority.Key), leaf, authority), RevocationStatus.Revoked);
			await AssertStatusAsync(Check(new Basic { ResponderId = ResponderByName(authority.Name), Responses = [unknown, good] }.Decode(authority.Key), leaf, authority), RevocationStatus.Unknown);
			await AssertStatusAsync(Check(new Basic { ResponderId = ResponderByName(authority.Name), Responses = [new SingleEntry { CertificateId = otherId, Status = Revoked(Now, 1) }.Encode(), good] }.Decode(authority.Key), leaf, authority), RevocationStatus.Good);
		}
	}

	// RFC 6960, Sec. 4.1.2: an extension that is not understood matters only if it is critical.
	[Test]
	public async Task CriticalExtensionsThatAreNotUnderstoodMakeTheResponseInvalid()
	{
		using TestPki.Authority authority = TestPki.Authority.CreateRoot("CN=OCSP CA");
		Certificate leaf = authority.IssueLeaf();
		byte[] certificateId = CertificateIdOf(leaf, authority.Certificate);
		Basic basic = new() { ResponderId = ResponderByName(authority.Name), Responses = [new SingleEntry { CertificateId = certificateId }.Encode()] };
		byte[] unknownCritical = Extension(PrivateOid, [0x05, 0x00], Critical);
		byte[] unknownNoncritical = Extension(PrivateOid, [0x05, 0x00]);
		byte[] nonceCritical = Extension(NonceOid, Tlv(0x04, [0x01]), Critical);

		using (Assert.Multiple())
		{
			await AssertStatusAsync(Check((basic with { Extensions = [unknownCritical] }).Decode(authority.Key), leaf, authority), RevocationStatus.Invalid);
			await AssertStatusAsync(Check((basic with { Extensions = [unknownNoncritical] }).Decode(authority.Key), leaf, authority), RevocationStatus.Good);
			await AssertStatusAsync(Check((basic with { Extensions = [nonceCritical] }).Decode(authority.Key), leaf, authority), RevocationStatus.Good);
			await AssertStatusAsync(Check((basic with { Responses = [new SingleEntry { CertificateId = certificateId, Extensions = [unknownCritical] }.Encode()] }).Decode(authority.Key), leaf, authority), RevocationStatus.Invalid);
			await AssertStatusAsync(Check((basic with { Responses = [new SingleEntry { CertificateId = certificateId, Extensions = [unknownNoncritical] }.Encode()] }).Decode(authority.Key), leaf, authority), RevocationStatus.Good);
		}
	}

	// A response's nonce is read if it is well formed; any other is reported as absent, and a client that sent none ignores it.
	[Test]
	public async Task MalformedNoncesAreIgnored()
	{
		using TestPki.Authority authority = TestPki.Authority.CreateRoot("CN=OCSP CA");
		Certificate leaf = authority.IssueLeaf();
		byte[] certificateId = CertificateIdOf(leaf, authority.Certificate);
		Basic basic = new() { ResponderId = ResponderByName(authority.Name), Responses = [new SingleEntry { CertificateId = certificateId }.Encode()] };
		byte[] nonce = new byte[16];
		OcspResponse notWrapped = (basic with { Extensions = [Extension(NonceOid, nonce)] }).Decode(authority.Key);
		OcspResponse empty = (basic with { Extensions = [Nonce([])] }).Decode(authority.Key);
		OcspResponse tooLong = (basic with { Extensions = [Nonce(new byte[33])] }).Decode(authority.Key);
		OcspResponse matching = (basic with { Extensions = [Nonce(nonce)] }).Decode(authority.Key);

		using (Assert.Multiple())
		{
			await Assert.That(matching.Nonce?.ToArray()).IsEquivalentTo(nonce, CollectionOrdering.Matching);
			await AssertStatusAsync(Check(matching, leaf, authority), RevocationStatus.Good);

			foreach (OcspResponse response in (OcspResponse[])[notWrapped, empty, tooLong])
			{
				await Assert.That(response.Nonce).IsNull();
				await AssertStatusAsync(Check(response, leaf, authority), RevocationStatus.Good);
			}
		}
	}

	[Test]
	[SuppressMessage("ReSharper", "AccessToDisposedClosure", Justification = "Assertions are awaited before the authority is disposed.")]
	public async Task TheCertsFieldToleratesWhatIsNotACertificate()
	{
		using TestPki.Authority authority = TestPki.Authority.CreateRoot("CN=OCSP CA");
		Certificate leaf = authority.IssueLeaf();
		byte[] certificateId = CertificateIdOf(leaf, authority.Certificate);
		Basic basic = new() { ResponderId = ResponderByName(authority.Name), Responses = [new SingleEntry { CertificateId = certificateId }.Encode()] };
		OcspResponse response = (basic with { Certificates = [[0x30, 0x00], leaf.Encoded.ToArray(), [0x04, 0x01, 0xFF]] }).Decode(authority.Key);

		using (Assert.Multiple())
		{
			await Assert.That(response.Certificates.Single().Encoded.ToArray()).IsEquivalentTo(leaf.Encoded.ToArray(), CollectionOrdering.Matching);
			await Assert.That(() => OcspResponse.Decode((basic with { Certificates = [[0xFF]] }).Encode(authority.Key))).Throws<ArgumentException>();
		}
	}

	// Each rule of RFC 6960, Sec. 4.2.2.2, for a delegated responder.
	[Test]
	public async Task DelegatedRespondersMustBeAuthorized()
	{
		using TestPki.Authority authority = TestPki.Authority.CreateRoot("CN=OCSP CA");
		using EcdsaP256 responderKey = EcdsaP256.GenerateKey();
		using EcdsaP256 otherKey = EcdsaP256.GenerateKey();
		using TestPki.Authority other = TestPki.Authority.CreateRoot("CN=Other CA");
		Certificate leaf = authority.IssueLeaf();
		byte[] certificateId = CertificateIdOf(leaf, authority.Certificate);
		byte[] publicKey = Signatures.SignatureTestUtils.ExportSubjectPublicKeyInfo(responderKey);
		byte[] subject = Name("CN=Delegated Responder");
		CertificateExtension signing = TestPki.ExtendedKeyUsage(OcspSigningOid);
		TestPki.Template template = new() { Subject = subject, SubjectPublicKeyInfo = publicKey, Extensions = [signing] };

		RevocationResult Evaluate(Certificate responder, ISignatureKey? signWith = null)
		{
			Basic basic = new() { ResponderId = ResponderByKey(responder), Responses = [new SingleEntry { CertificateId = certificateId }.Encode()], Certificates = [responder.Encoded.ToArray()] };
			return Check(basic.Decode(signWith ?? responderKey), leaf, authority);
		}

		Certificate valid = authority.Issue(template);
		Certificate withNoCheck = authority.Issue(template with { Extensions = [signing, new CertificateExtension(NoCheckOid, false, NullValue)] });
		Certificate noCheckNotNull = authority.Issue(template with { Extensions = [signing, new CertificateExtension(NoCheckOid, false, (byte[])[0x02, 0x01, 0x00])] });
		Certificate noEku = authority.Issue(template with { Extensions = [] });
		Certificate serverAuth = authority.Issue(template with { Extensions = [TestPki.ExtendedKeyUsage(ServerAuthenticationOid)] });
		Certificate anyEku = authority.Issue(template with { Extensions = [TestPki.ExtendedKeyUsage(TestPki.AnyExtendedKeyUsageOid)] });
		Certificate noSignatureUsage = authority.Issue(template with { Extensions = [signing, TestPki.KeyUsage(X509KeyUsageFlags.KeyEncipherment)] });
		Certificate withSignatureUsage = authority.Issue(template with { Extensions = [signing, TestPki.KeyUsage(X509KeyUsageFlags.DigitalSignature)] });
		Certificate expired = authority.Issue(template with { NotBefore = Now.AddDays(-30), NotAfter = Now.AddDays(-1) });
		Certificate future = authority.Issue(template with { NotBefore = Now.AddDays(1), NotAfter = Now.AddDays(30) });
		Certificate byOtherAuthority = other.Issue(template);
		Certificate unknownCritical = authority.Issue(template with { Extensions = [signing, new CertificateExtension(PrivateOid, true, NullValue)] });

		using (Assert.Multiple())
		{
			await AssertStatusAsync(Evaluate(valid), RevocationStatus.Good);
			await AssertStatusAsync(Evaluate(withNoCheck), RevocationStatus.Good);
			await AssertStatusAsync(Evaluate(withSignatureUsage), RevocationStatus.Good);
			await AssertStatusAsync(Evaluate(noCheckNotNull), RevocationStatus.Invalid);
			await AssertStatusAsync(Evaluate(noEku), RevocationStatus.Invalid);
			await AssertStatusAsync(Evaluate(serverAuth), RevocationStatus.Invalid);
			await AssertStatusAsync(Evaluate(anyEku), RevocationStatus.Invalid);
			await AssertStatusAsync(Evaluate(noSignatureUsage), RevocationStatus.Invalid);
			await AssertStatusAsync(Evaluate(expired), RevocationStatus.Invalid);
			await AssertStatusAsync(Evaluate(future), RevocationStatus.Invalid);
			await AssertStatusAsync(Evaluate(byOtherAuthority), RevocationStatus.Invalid);
			await AssertStatusAsync(Evaluate(unknownCritical), RevocationStatus.Invalid);

			// The response's signature and the certificate's must both verify.
			await AssertStatusAsync(Evaluate(valid, otherKey), RevocationStatus.Invalid);

			Certificate wrongSignature = Certificate.Decode(WithCorruptedSignature(valid));
			await AssertStatusAsync(Evaluate(wrongSignature), RevocationStatus.Invalid);
		}
	}

	// RFC 9608, Sec. 3: a delegated responder's certificate that breaks the rules for noRevAvail is invalid.
	[Test]
	public async Task ADelegatedResponderFollowsTheRulesOfNoRevAvail()
	{
		const string noRevAvailOid = "2.5.29.56";
		const string crlDistributionPointsOid = "2.5.29.31";
		const string freshestCrlOid = "2.5.29.46";
		const string authorityInformationAccessOid = "1.3.6.1.5.5.7.1.1";

		using TestPki.Authority authority = TestPki.Authority.CreateRoot("CN=OCSP CA");
		using EcdsaP256 responderKey = EcdsaP256.GenerateKey();
		Certificate leaf = authority.IssueLeaf();
		CertificateExtension signing = TestPki.ExtendedKeyUsage(OcspSigningOid);
		CertificateExtension noRevAvail = new(noRevAvailOid, false, NullValue);
		TestPki.Template template = new() { Subject = Name("CN=Delegated Responder"), SubjectPublicKeyInfo = Signatures.SignatureTestUtils.ExportSubjectPublicKeyInfo(responderKey) };

		RevocationResult Evaluate(params CertificateExtension[] more)
		{
			Certificate responder = authority.Issue(template with { Extensions = [signing, .. more] });
			Basic basic = new() { ResponderId = ResponderByKey(responder), Responses = [new SingleEntry { CertificateId = CertificateIdOf(leaf, authority.Certificate) }.Encode()], Certificates = [responder.Encoded.ToArray()] };
			return Check(basic.Decode(responderKey), leaf, authority);
		}

		static CertificateExtension Access(string method)
		{
			return new CertificateExtension(authorityInformationAccessOid, false, Sequence(Sequence(Oid(method), TestPki.UniformResourceIdentifier("http://responder.test/"))));
		}

		using (Assert.Multiple())
		{
			await AssertStatusAsync(Evaluate(noRevAvail), RevocationStatus.Good);
			await AssertStatusAsync(Evaluate(noRevAvail, Access("1.3.6.1.5.5.7.48.2")), RevocationStatus.Good);
			await AssertStatusAsync(Evaluate(new CertificateExtension(noRevAvailOid, false, (byte[])[0x02, 0x01, 0x00])), RevocationStatus.Invalid);
			await AssertStatusAsync(Evaluate(noRevAvail, TestPki.BasicConstraints(true)), RevocationStatus.Invalid);
			await AssertStatusAsync(Evaluate(noRevAvail, new CertificateExtension(crlDistributionPointsOid, false, (byte[])[0x30, 0x00])), RevocationStatus.Invalid);
			await AssertStatusAsync(Evaluate(noRevAvail, new CertificateExtension(freshestCrlOid, false, (byte[])[0x30, 0x00])), RevocationStatus.Invalid);
			await AssertStatusAsync(Evaluate(noRevAvail, Access("1.3.6.1.5.5.7.48.1")), RevocationStatus.Invalid);
		}
	}

	// A response that names many certificates as its responder cannot make the checker verify without bound.
	[Test]
	public async Task ManyCandidatesAreBounded()
	{
		using TestPki.Authority authority = TestPki.Authority.CreateRoot("CN=OCSP CA");
		using EcdsaP256 responderKey = EcdsaP256.GenerateKey();
		Certificate leaf = authority.IssueLeaf();
		byte[] publicKey = Signatures.SignatureTestUtils.ExportSubjectPublicKeyInfo(responderKey);
		byte[] subject = Name("CN=Delegated Responder");
		TestPki.Template template = new() { Subject = subject, SubjectPublicKeyInfo = publicKey, Extensions = [TestPki.ExtendedKeyUsage(OcspSigningOid)] };
		Certificate noEku = authority.Issue(template with { Extensions = [] });
		Certificate valid = authority.Issue(template);
		byte[][] certificates = [.. Enumerable.Repeat(noEku.Encoded.ToArray(), 8), valid.Encoded.ToArray()];
		Basic basic = new() { ResponderId = ResponderByName(subject), Responses = [new SingleEntry { CertificateId = CertificateIdOf(leaf, authority.Certificate) }.Encode()], Certificates = certificates };
		RevocationResult tooMany = Check(basic.Decode(responderKey), leaf, authority);
		RevocationResult enough = Check((basic with { Certificates = [.. Enumerable.Repeat(noEku.Encoded.ToArray(), 7), valid.Encoded.ToArray()] }).Decode(responderKey), leaf, authority);

		using (Assert.Multiple())
		{
			await AssertStatusAsync(tooMany, RevocationStatus.Invalid);
			await AssertStatusAsync(enough, RevocationStatus.Good);
		}
	}

	// RFC 6960, Sec. 4.2.2.2: a byName ResponderID does not tell a delegated responder that has the name of its CA from that CA, whose key is the first tried.
	[Test]
	public async Task ADelegatedResponderMayHaveTheNameOfTheCa()
	{
		using TestPki.Authority authority = TestPki.Authority.CreateRoot("CN=OCSP CA");
		using EcdsaP256 responderKey = EcdsaP256.GenerateKey();
		using EcdsaP256 otherKey = EcdsaP256.GenerateKey();
		Certificate leaf = authority.IssueLeaf();
		TestPki.Template template = new() { Subject = authority.Name, SubjectPublicKeyInfo = Signatures.SignatureTestUtils.ExportSubjectPublicKeyInfo(responderKey), Extensions = [TestPki.ExtendedKeyUsage(OcspSigningOid)] };
		Certificate responder = authority.Issue(template);
		Certificate noEku = authority.Issue(template with { Extensions = [] });
		Basic basic = new() { ResponderId = ResponderByName(authority.Name), Responses = [new SingleEntry { CertificateId = CertificateIdOf(leaf, authority.Certificate) }.Encode()], Certificates = [responder.Encoded.ToArray()] };

		using (Assert.Multiple())
		{
			await AssertStatusAsync(Check(basic.Decode(responderKey), leaf, authority), RevocationStatus.Good);
			await AssertStatusAsync(Check(basic.Decode(authority.Key), leaf, authority), RevocationStatus.Good);
			await AssertStatusAsync(Check(basic.Decode(otherKey), leaf, authority), RevocationStatus.Invalid);
			await AssertStatusAsync(Check((basic with { Certificates = [noEku.Encoded.ToArray()] }).Decode(responderKey), leaf, authority), RevocationStatus.Invalid);
			await AssertStatusAsync(Check((basic with { Certificates = null }).Decode(responderKey), leaf, authority), RevocationStatus.Invalid);
		}
	}

	[Test]
	[SuppressMessage("ReSharper", "AccessToDisposedClosure", Justification = "Assertions are awaited before the authority is disposed.")]
	public async Task CertificateIdentifiersCheckTheirFields()
	{
		using TestPki.Authority authority = TestPki.Authority.CreateRoot("CN=OCSP CA");
		Certificate leaf = authority.IssueLeaf();
		Certificate other = authority.Issue(new TestPki.Template { SerialNumber = [0x02], Subject = Name("CN=Other"), SubjectPublicKeyInfo = leaf.PublicKeyInfo.Encoded.ToArray() });
		byte[] name = leaf.Issuer.ToArray();
		byte[] key = authority.Certificate.PublicKeyInfo.PublicKey.ToArray();
		OcspCertificateId matching = IdOf(CertificateIdOf(leaf, name, key));

		using (Assert.Multiple())
		{
			await Assert.That(matching.Matches(leaf, authority.Certificate)).IsTrue();
			await Assert.That(IdOf(CertificateIdOf(leaf, [0x01], key)).Matches(leaf, authority.Certificate)).IsFalse();
			await Assert.That(IdOf(CertificateIdOf(leaf, name, [0x01])).Matches(leaf, authority.Certificate)).IsFalse();
			await Assert.That(matching.Matches(other, authority.Certificate)).IsFalse();
			await Assert.That(() => matching.Matches(null!, authority.Certificate)).Throws<ArgumentNullException>();
			await Assert.That(() => matching.Matches(leaf, null!)).Throws<ArgumentNullException>();
			await Assert.That(IdOf(Sequence(Sequence(Oid("1.2.840.113549.2.5"), [0x05, 0x00]), Tlv(0x04, new byte[16]), Tlv(0x04, new byte[16]), Tlv(0x02, leaf.SerialNumber.ToArray()))).Matches(leaf, authority.Certificate)).IsFalse();
		}

		static OcspCertificateId IdOf(byte[] encoded)
		{
			DerReader reader = new(encoded);
			OcspCertificateId id = OcspCertificateId.Read(ref reader);
			return id;
		}
	}

	private static byte[] WithCorruptedSignature(Certificate certificate)
	{
		byte[] encoded = certificate.Encoded.ToArray();
		encoded[^1] ^= 0x01;
		return encoded;
	}
}
