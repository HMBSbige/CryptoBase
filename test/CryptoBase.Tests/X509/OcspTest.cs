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

	// RFC 9654, Sec. 2.1: a nonce of 1 to 128 bytes. The longest takes the long form of the lengths, and the nonce ends the request.
	[Test]
	public async Task RequestsAcceptNoncesOfOneTo128Bytes()
	{
		byte[] longest = [.. Enumerable.Range(0, 128).Select(static i => (byte)i)];
		byte[] end = [0x04, 0x81, 0x83, 0x04, 0x81, 0x80, .. longest];
		OcspRequest withLongest = OcspRequest.Create(GoodLeaf, CA, longest);

		using (Assert.Multiple())
		{
			await Assert.That(OcspRequest.Create(GoodLeaf, CA, new byte[1]).Nonce?.Length).IsEqualTo(1);
			await Assert.That(OcspRequest.Create(GoodLeaf, CA, new byte[32]).Nonce?.Length).IsEqualTo(32);
			await Assert.That(OcspRequest.Create(GoodLeaf, CA, new byte[33]).Nonce?.Length).IsEqualTo(33);
			await Assert.That(withLongest.Nonce?.ToArray()).IsEquivalentTo(longest, CollectionOrdering.Matching);
			await Assert.That(withLongest.Encoded.Span.EndsWith(end)).IsTrue();
			await Assert.That(() => OcspRequest.Create(GoodLeaf, CA, new byte[129])).Throws<ArgumentException>();
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
			await Assert.That((byName.Responder as OcspResponderId.ByName)?.Name.ToArray()).IsEquivalentTo(CA.Subject.ToArray(), CollectionOrdering.Matching);
			await Assert.That((byKey.Responder as OcspResponderId.ByKey)?.KeyHash.Length).IsEqualTo(20);
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

	// The skew is compared with the distance to each end of the interval, which a time within the skew of the limits of DateTimeOffset cannot overflow.
	[Test]
	public async Task TheClockSkewHoldsAtTheLimitsOfTime()
	{
		using TestPki.Authority authority = TestPki.Authority.CreateRoot("CN=OCSP CA");
		Certificate leaf = authority.IssueLeaf();
		byte[] certificateId = CertificateIdOf(leaf, authority.Certificate);
		DateTimeOffset last = new(9999, 12, 31, 23, 59, 59, TimeSpan.Zero);
		DateTimeOffset first = new(1, 1, 1, 0, 0, 0, TimeSpan.Zero);
		TimeSpan interval = TimeSpan.FromMinutes(10);
		OcspResponse late = new Basic { ResponderId = ResponderByName(authority.Name), Responses = [new SingleEntry { CertificateId = certificateId, ThisUpdate = Time(last - interval, generalized: true), NextUpdate = Time(last, generalized: true) }.Encode()] }.Decode(authority.Key);
		OcspResponse early = new Basic { ResponderId = ResponderByName(authority.Name), Responses = [new SingleEntry { CertificateId = certificateId, ThisUpdate = Time(first, generalized: true), NextUpdate = Time(first + interval, generalized: true) }.Encode()] }.Decode(authority.Key);

		using (Assert.Multiple())
		{
			await AssertStatusAsync(Check(late, leaf, authority, DateTimeOffset.MaxValue), RevocationStatus.Good);
			await AssertStatusAsync(Check(late, leaf, authority, last - interval - RevocationChecker.OcspClockSkew - TimeSpan.FromSeconds(1)), RevocationStatus.Invalid);
			await AssertStatusAsync(Check(early, leaf, authority, DateTimeOffset.MinValue), RevocationStatus.Good);
			await AssertStatusAsync(Check(early, leaf, authority, first + interval + RevocationChecker.OcspClockSkew + TimeSpan.FromSeconds(1)), RevocationStatus.Invalid);
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

	// Each end is within the clock skew of now, which would accept it alone; together they end before they begin.
	[Test]
	public async Task AValidityIntervalThatEndsBeforeItBeginsIsInvalid()
	{
		using TestPki.Authority authority = TestPki.Authority.CreateRoot("CN=OCSP CA");
		Certificate leaf = authority.IssueLeaf();
		byte[] certificateId = CertificateIdOf(leaf, authority.Certificate);

		RevocationResult Evaluate(DateTimeOffset thisUpdate, DateTimeOffset nextUpdate)
		{
			SingleEntry single = new() { CertificateId = certificateId, ThisUpdate = Time(thisUpdate, generalized: true), NextUpdate = Time(nextUpdate, generalized: true) };
			return Check(new Basic { ResponderId = ResponderByName(authority.Name), Responses = [single.Encode()] }.Decode(authority.Key), leaf, authority);
		}

		RevocationResult inverted = Evaluate(Now.AddMinutes(4), Now.AddMinutes(-4));

		using (Assert.Multiple())
		{
			await AssertStatusAsync(inverted, RevocationStatus.Invalid);
			await Assert.That(inverted.Detail).IsEqualTo("The response's nextUpdate is before its thisUpdate.");
			await AssertStatusAsync(Evaluate(Now, Now), RevocationStatus.Good);
		}
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

	// Sec. 4.2.2.1: a response for the certificate that is not current tells nothing, so of several, the most severe of those that are current stands, whatever their order; one of those with a critical extension that is not understood makes the response invalid. Without a current one, the problem of the most severe stands.
	[Test]
	public async Task SeveralResponsesTakeTheMostSevereThatIsCurrent()
	{
		using TestPki.Authority authority = TestPki.Authority.CreateRoot("CN=OCSP CA");
		Certificate leaf = authority.IssueLeaf();
		byte[] certificateId = CertificateIdOf(leaf, authority.Certificate);
		SingleEntry current = new() { CertificateId = certificateId };
		SingleEntry expired = current with { ThisUpdate = Time(Now.AddDays(-3), generalized: true), NextUpdate = Time(Now.AddDays(-2), generalized: true) };
		SingleEntry notYetValid = current with { ThisUpdate = Time(Now.AddDays(1), generalized: true), NextUpdate = Time(Now.AddDays(2), generalized: true) };
		byte[] unknownCritical = Extension(PrivateOid, [0x05, 0x00], Critical);
		byte[] good = current.Encode();
		byte[] goodSooner = (current with { NextUpdate = Time(Now.AddMinutes(30), generalized: true) }).Encode();
		byte[] expiredGood = expired.Encode();
		byte[] expiredRevoked = (expired with { Status = Revoked(Now.AddDays(-4), 1) }).Encode();
		byte[] notYetRevoked = (notYetValid with { Status = Revoked(Now.AddDays(-4), 1) }).Encode();
		byte[] revokedWithCritical = (current with { Status = Revoked(Now.AddDays(-1), 1), Extensions = [unknownCritical] }).Encode();
		byte[] goodWithCritical = (current with { Extensions = [unknownCritical] }).Encode();
		byte[] expiredWithCritical = (expired with { Extensions = [unknownCritical] }).Encode();

		static RevocationResult Evaluate(TestPki.Authority authority, Certificate leaf, params byte[][] responses)
		{
			return Check(new Basic { ResponderId = ResponderByName(authority.Name), Responses = responses }.Decode(authority.Key), leaf, authority);
		}

		static async Task AssertEitherOrder(TestPki.Authority authority, Certificate leaf, byte[] first, byte[] second, RevocationStatus expected)
		{
			await AssertStatusAsync(Evaluate(authority, leaf, first, second), expected);
			await AssertStatusAsync(Evaluate(authority, leaf, second, first), expected);
		}

		using (Assert.Multiple())
		{
			await AssertEitherOrder(authority, leaf, expiredGood, good, RevocationStatus.Good);
			await AssertEitherOrder(authority, leaf, expiredRevoked, good, RevocationStatus.Good);
			await AssertEitherOrder(authority, leaf, notYetRevoked, good, RevocationStatus.Good);
			await AssertEitherOrder(authority, leaf, expiredWithCritical, good, RevocationStatus.Good);
			await AssertEitherOrder(authority, leaf, revokedWithCritical, good, RevocationStatus.Invalid);
			await AssertEitherOrder(authority, leaf, goodWithCritical, good, RevocationStatus.Invalid);
			await AssertEitherOrder(authority, leaf, expiredRevoked, expiredGood, RevocationStatus.Invalid);
			await Assert.That(Evaluate(authority, leaf, good, goodSooner).NextUpdate).IsEqualTo(Now.AddMinutes(30));
			await Assert.That(Evaluate(authority, leaf, goodSooner, good).NextUpdate).IsEqualTo(Now.AddMinutes(30));

			// The problem of the most severe that is not current, its critical extension before its times.
			await Assert.That(Evaluate(authority, leaf, expiredGood, notYetRevoked).Detail).IsEqualTo("The response is not yet valid.");
			await Assert.That(Evaluate(authority, leaf, expiredGood).Detail).IsEqualTo("The response has expired.");
			await Assert.That(Evaluate(authority, leaf, expiredWithCritical).Detail).StartsWith("The response for the certificate");
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

	// RFC 6960, Sec. 4.1.2: what the checker understands differs between the two levels, so an extension of the single responses is refused on the response.
	[Test]
	[Arguments(ExtendedRevokeOid, true)]
	[Arguments(CrlReferenceOid, false)]
	[Arguments(ArchiveCutoffOid, false)]
	[Arguments(ReasonCodeOid, false)]
	[Arguments(InvalidityDateOid, false)]
	public async Task CriticalExtensionsOfTheResponseMustBeUnderstoodThere(string oid, bool understood)
	{
		using TestPki.Authority authority = TestPki.Authority.CreateRoot("CN=OCSP CA");
		Certificate leaf = authority.IssueLeaf();
		Basic basic = new() { ResponderId = ResponderByName(authority.Name), Responses = [new SingleEntry { CertificateId = CertificateIdOf(leaf, authority.Certificate) }.Encode()], Extensions = [Extension(oid, NullValue, Critical)] };
		RevocationResult result = Check(basic.Decode(authority.Key), leaf, authority);

		using (Assert.Multiple())
		{
			await AssertStatusAsync(result, understood ? RevocationStatus.Good : RevocationStatus.Invalid);
			await Assert.That(result.Detail).IsEqualTo(understood ? null : $"The response has the critical extension {oid}, which the checker does not process.");
		}
	}

	[Test]
	[Arguments(CrlReferenceOid, true)]
	[Arguments(ArchiveCutoffOid, true)]
	[Arguments(ReasonCodeOid, true)]
	[Arguments(InvalidityDateOid, true)]
	[Arguments(NonceOid, false)]
	[Arguments(ExtendedRevokeOid, false)]
	public async Task CriticalExtensionsOfASingleResponseMustBeUnderstoodThere(string oid, bool understood)
	{
		using TestPki.Authority authority = TestPki.Authority.CreateRoot("CN=OCSP CA");
		Certificate leaf = authority.IssueLeaf();
		Basic basic = new() { ResponderId = ResponderByName(authority.Name), Responses = [new SingleEntry { CertificateId = CertificateIdOf(leaf, authority.Certificate), Extensions = [Extension(oid, WellFormedValueOf(oid), Critical)] }.Encode()] };
		RevocationResult result = Check(basic.Decode(authority.Key), leaf, authority);

		using (Assert.Multiple())
		{
			await AssertStatusAsync(result, understood ? RevocationStatus.Good : RevocationStatus.Invalid);
			await Assert.That(result.Detail).IsEqualTo(understood ? null : $"The response for the certificate has the critical extension {oid}, which the checker does not process.");
		}
	}

	public static IEnumerable<Func<(string Case, bool Single, string Oid, byte[] Value)>> MalformedExtensions()
	{
		yield return () => ("extendedRevoke as an OCTET STRING", false, ExtendedRevokeOid, Tlv(0x04, []));
		yield return () => ("extendedRevoke empty", false, ExtendedRevokeOid, []);
		yield return () => ("crlID as NULL", true, CrlReferenceOid, NullValue);
		yield return () => ("crlID with a URL beyond ASCII", true, CrlReferenceOid, Sequence(Tlv(0xA0, Tlv(0x16, [0x80]))));
		yield return () => ("crlID with a number that is not minimal", true, CrlReferenceOid, Sequence(Tlv(0xA1, Tlv(0x02, [0x00, 0x01]))));
		yield return () => ("crlID with a field that it does not have", true, CrlReferenceOid, Sequence(Tlv(0xA3, NullValue)));
		yield return () => ("archiveCutoff as NULL", true, ArchiveCutoffOid, NullValue);
		yield return () => ("archiveCutoff empty", true, ArchiveCutoffOid, []);
		yield return () => ("archiveCutoff as a UTCTime", true, ArchiveCutoffOid, Time(Now));
		yield return () => ("archiveCutoff followed by another value", true, ArchiveCutoffOid, [.. Time(Now, generalized: true), .. NullValue]);
		yield return () => ("reasonCode as NULL", true, ReasonCodeOid, NullValue);
		yield return () => ("reasonCode with a value that is not defined", true, ReasonCodeOid, [0x0A, 0x01, 0x07]);
		yield return () => ("invalidityDate as NULL", true, InvalidityDateOid, NullValue);
	}

	// RFC 6960, Sec. 4.1.2: an extension that the checker understands by its type is processed only if its value decodes as that type; a noncritical one that does not is ignored, as one not understood.
	[Test]
	[MethodDataSource(nameof(MalformedExtensions))]
	public async Task CriticalExtensionsMustDecodeAsTheirType(string @case, bool single, string oid, byte[] value)
	{
		using TestPki.Authority authority = TestPki.Authority.CreateRoot("CN=OCSP CA");
		Certificate leaf = authority.IssueLeaf();
		byte[] certificateId = CertificateIdOf(leaf, authority.Certificate);

		RevocationResult Evaluate(byte[]? critical)
		{
			byte[] extension = Extension(oid, value, critical);
			Basic basic = single
				? new Basic { ResponderId = ResponderByName(authority.Name), Responses = [new SingleEntry { CertificateId = certificateId, Extensions = [extension] }.Encode()] }
				: new Basic { ResponderId = ResponderByName(authority.Name), Responses = [new SingleEntry { CertificateId = certificateId }.Encode()], Extensions = [extension] };
			return Check(basic.Decode(authority.Key), leaf, authority);
		}

		RevocationResult critical = Evaluate(Critical);

		using (Assert.Multiple())
		{
			await Assert.That(critical.Status).IsEqualTo(RevocationStatus.Invalid).Because(@case);
			await Assert.That(critical.Detail).IsEqualTo($"{(single ? "The response for the certificate" : "The response")} has the critical extension {oid}, whose value does not decode.").Because(@case);
			await Assert.That(Evaluate(null).Status).IsEqualTo(RevocationStatus.Good).Because(@case);
		}
	}

	// A value of the type of each extension that the checker understands, which it decodes before it accepts one that is critical.
	private static byte[] WellFormedValueOf(string oid)
	{
		return oid switch
		{
			CrlReferenceOid => Sequence(Tlv(0xA0, Tlv(0x16, "http://crl.example/ca.crl"u8.ToArray())), Tlv(0xA1, Tlv(0x02, [0x01])), Tlv(0xA2, Time(Now, generalized: true))),
			ArchiveCutoffOid or InvalidityDateOid => Time(Now, generalized: true),
			ReasonCodeOid => [0x0A, 0x01, 0x01],
			_ => NullValue
		};
	}

	// A response's nonce is read if it is well formed, which is 1 to 128 bytes (RFC 9654, Sec. 2.1); any other is reported as absent, and a client that sent none ignores it.
	[Test]
	public async Task MalformedNoncesAreIgnored()
	{
		using TestPki.Authority authority = TestPki.Authority.CreateRoot("CN=OCSP CA");
		Certificate leaf = authority.IssueLeaf();
		byte[] certificateId = CertificateIdOf(leaf, authority.Certificate);
		Basic basic = new() { ResponderId = ResponderByName(authority.Name), Responses = [new SingleEntry { CertificateId = certificateId }.Encode()] };
		byte[] nonce = new byte[16];
		byte[] longestNonce = [.. Enumerable.Range(0, 128).Select(static i => (byte)i)];
		OcspResponse notWrapped = (basic with { Extensions = [Extension(NonceOid, nonce)] }).Decode(authority.Key);
		OcspResponse empty = (basic with { Extensions = [Nonce([])] }).Decode(authority.Key);
		OcspResponse tooLong = (basic with { Extensions = [Nonce(new byte[129])] }).Decode(authority.Key);
		OcspResponse matching = (basic with { Extensions = [Nonce(nonce)] }).Decode(authority.Key);
		OcspResponse longest = (basic with { Extensions = [Nonce(longestNonce)] }).Decode(authority.Key);

		using (Assert.Multiple())
		{
			await Assert.That(matching.Nonce?.ToArray()).IsEquivalentTo(nonce, CollectionOrdering.Matching);
			await AssertStatusAsync(Check(matching, leaf, authority), RevocationStatus.Good);
			await Assert.That(longest.Nonce?.ToArray()).IsEquivalentTo(longestNonce, CollectionOrdering.Matching);
			await AssertStatusAsync(Check(longest, leaf, authority), RevocationStatus.Good);

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

	// The responder's certificate is checked against its issuer alone, so a name that the issuer's constraints exclude does not make it invalid: its names give it no authority.
	[Test]
	public async Task NameConstraintsDoNotApplyToADelegatedResponder()
	{
		byte[] subject = Name("CN=Delegated Responder");
		using TestPki.Authority authority = TestPki.Authority.CreateRoot("CN=OCSP CA", more: [TestPki.NameConstraints(null, [TestPki.DirectoryName(subject)])]);
		using EcdsaP256 responderKey = EcdsaP256.GenerateKey();
		Certificate leaf = authority.IssueLeaf();
		Certificate responder = authority.Issue(new TestPki.Template { Subject = subject, SubjectPublicKeyInfo = Signatures.SignatureTestUtils.ExportSubjectPublicKeyInfo(responderKey), Extensions = [TestPki.ExtendedKeyUsage(OcspSigningOid)] });
		Basic basic = new() { ResponderId = ResponderByKey(responder), Responses = [new SingleEntry { CertificateId = CertificateIdOf(leaf, authority.Certificate) }.Encode()], Certificates = [responder.Encoded.ToArray()] };

		await AssertStatusAsync(Check(basic.Decode(responderKey), leaf, authority), RevocationStatus.Good);
	}

	[Test]
	public async Task ADelegatedResponderMayHaveCriticalExtensionsThatTheCheckerProcesses()
	{
		using TestPki.Authority authority = TestPki.Authority.CreateRoot("CN=OCSP CA");
		using EcdsaP256 responderKey = EcdsaP256.GenerateKey();
		Certificate leaf = authority.IssueLeaf();
		CertificateExtension signing = TestPki.ExtendedKeyUsage(OcspSigningOid);
		TestPki.Template template = new() { Subject = Name("CN=Delegated Responder"), SubjectPublicKeyInfo = Signatures.SignatureTestUtils.ExportSubjectPublicKeyInfo(responderKey) };

		RevocationResult Evaluate(params CertificateExtension[] extensions)
		{
			Certificate responder = authority.Issue(template with { Extensions = extensions });
			Basic basic = new() { ResponderId = ResponderByKey(responder), Responses = [new SingleEntry { CertificateId = CertificateIdOf(leaf, authority.Certificate) }.Encode()], Certificates = [responder.Encoded.ToArray()] };
			return Check(basic.Decode(responderKey), leaf, authority);
		}

		RevocationResult unknown = Evaluate(signing, new CertificateExtension(PrivateOid, true, NullValue));

		using (Assert.Multiple())
		{
			await AssertStatusAsync(Evaluate(signing, TestPki.BasicConstraints(false)), RevocationStatus.Good);
			await AssertStatusAsync(Evaluate(new CertificateExtension(signing.Oid, true, signing.Value.Span)), RevocationStatus.Good);
			await AssertStatusAsync(Evaluate(signing, TestPki.SubjectAlternativeNames(true, TestPki.Rfc822Name("ocsp@example.test"))), RevocationStatus.Good);
			await AssertStatusAsync(Evaluate(signing, TestPki.SubjectAlternativeNames(true, Tlv(0xA3, Sequence()), Tlv(0xA5, Tlv(0xA1, [0x0C, 0x01, 0x61])))), RevocationStatus.Good);
			await AssertStatusAsync(Evaluate(signing, new CertificateExtension(NoCheckOid, true, NullValue)), RevocationStatus.Good);
			await Assert.That(unknown.Detail).IsEqualTo($"The responder's certificate has the critical extension {PrivateOid}, which the checker does not process.");
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

	// RFC 6960, Sec. 4.2.2.3: a byName ResponderID is a Name, which matches the subject of the CA or of a delegated responder by RFC 5280, Sec. 7.1, in another string type, case or spacing; the signature is verified all the same. A name that the exact comparison cannot find the same, as it differs in the case of a letter beyond ASCII, names neither.
	[Test]
	public async Task AResponderNameMatchesTheSubjectByRfc5280()
	{
		using TestPki.Authority authority = TestPki.Authority.CreateRoot("CN=OCSP CA");
		using EcdsaP256 responderKey = EcdsaP256.GenerateKey();
		Certificate leaf = authority.IssueLeaf();
		TestPki.Template template = new() { Subject = CommonName(PrintableStringTag, "Delegated Responder"), SubjectPublicKeyInfo = Signatures.SignatureTestUtils.ExportSubjectPublicKeyInfo(responderKey), Extensions = [TestPki.ExtendedKeyUsage(OcspSigningOid)] };
		Certificate responder = authority.Issue(template);
		Certificate accented = authority.Issue(template with { Subject = CommonName(Utf8StringTag, "Répondeur") });
		Basic basic = new() { ResponderId = ResponderByName(CommonName(Utf8StringTag, "ocsp  ca ")), Responses = [new SingleEntry { CertificateId = CertificateIdOf(leaf, authority.Certificate) }.Encode()] };
		Basic delegated = basic with { ResponderId = ResponderByName(CommonName(Utf8StringTag, " DELEGATED responder")), Certificates = [responder.Encoded.ToArray()] };
		Basic otherCase = basic with { ResponderId = ResponderByName(CommonName(Utf8StringTag, "RÉPONDEUR")), Certificates = [accented.Encoded.ToArray()] };

		using (Assert.Multiple())
		{
			await AssertStatusAsync(Check(basic.Decode(authority.Key), leaf, authority), RevocationStatus.Good);
			await AssertStatusAsync(Check(basic.Decode(responderKey), leaf, authority), RevocationStatus.Invalid);
			await AssertStatusAsync(Check(delegated.Decode(responderKey), leaf, authority), RevocationStatus.Good);
			await AssertStatusAsync(Check(otherCase.Decode(responderKey), leaf, authority), RevocationStatus.Invalid);
			await AssertStatusAsync(Check((otherCase with { ResponderId = ResponderByName(CommonName(Utf8StringTag, "Répondeur")) }).Decode(responderKey), leaf, authority), RevocationStatus.Good);
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
