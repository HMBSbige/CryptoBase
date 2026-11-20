using CryptoBase.Abstractions.Signatures;
using CryptoBase.Signatures;
using CryptoBase.Signatures.Ecdsa;
using CryptoBase.X509;
using System.Diagnostics;
using System.Security.Cryptography.X509Certificates;
using static CryptoBase.Tests.Signatures.SignatureTestUtils;
using static CryptoBase.Tests.TestUtils;
using static CryptoBase.Tests.X509.TestPki;
using static CryptoBase.Tests.X509.TrustAnchorCertificateValidatorTest;
using static CryptoBase.Tests.X509.TrustAnchorRetrievalTest;
using static CryptoBase.Tests.X509.X509TestUtils;

namespace CryptoBase.Tests.X509;

// The OCSP response that the peer staples for its certificate (RFC 6066, Sec. 8; RFC 9846, Sec. 4.5.1.1), the interface members that tell TLS what to ask for and send, and how TrustAnchorCertificateValidator checks the response.
public class StapledOcspResponseTest
{
	private const string IssuerOcspUri = "http://ca-ocsp.test/";

	private static readonly byte[] Garbage = [0x01, 0x02, 0x03];

	// What makes a stapled response one that the validator does not accept.
	public enum Defect
	{
		Garbage,
		TryLater,
		NotBasic,
		OtherCertificate,
		UnauthorizedSigner,
		ExpiredResponder,
		BadSignature,
		Expired,
		NotYetValid,
		Unknown
	}

	private static async Task<CertificateValidationResult> Validate(ICertificateValidator validator, ReadOnlyMemory<byte> stapled, params Certificate[] presented)
	{
		return await validator.ValidateAsync(new CertificateValidationContext(presented, CertificateUsage.ServerAuthentication)
		{
			StapledOcspResponse = stapled,
			TimeProvider = new FixedTimeProvider(Now)
		});
	}

	// A response that the issuer signs, with one response for the certificate.
	private static byte[] Staple(Certificate certificate, Authority issuer, DateTimeOffset thisUpdate, DateTimeOffset nextUpdate, byte[]? status = null)
	{
		return new TestOcsp.Basic
		{
			ResponderId = TestOcsp.ResponderByKey(issuer.Certificate),
			Responses = [Entry(certificate, issuer, thisUpdate, nextUpdate, status)]
		}.Encode(issuer.Key);
	}

	private static byte[] Entry(Certificate certificate, Authority issuer, DateTimeOffset thisUpdate, DateTimeOffset nextUpdate, byte[]? status = null)
	{
		return new TestOcsp.SingleEntry
		{
			CertificateId = TestOcsp.CertificateIdOf(certificate, issuer.Certificate),
			Status = status ?? TestOcsp.Good,
			ThisUpdate = Time(thisUpdate, generalized: true),
			NextUpdate = Time(nextUpdate, generalized: true)
		}.Encode();
	}

	// A good response that a delegated responder, which the issuer issues with the given extensions, signs.
	private static byte[] SignedByDelegatedResponder(Certificate certificate, Authority issuer, CertificateExtension[] extensions, DateTimeOffset? notAfter = null)
	{
		using EcdsaP256 responderKey = EcdsaP256.GenerateKey();
		Certificate responder = issuer.Issue
		(
			new Template
			{
				Subject = Name("CN=Responder"),
				SerialNumber = [0x03],
				SubjectPublicKeyInfo = ExportSubjectPublicKeyInfo(responderKey),
				NotAfter = notAfter ?? Now.AddDays(30),
				Extensions = extensions
			}
		);

		return new TestOcsp.Basic
		{
			ResponderId = TestOcsp.ResponderByKey(responder),
			Certificates = [responder.Encoded.ToArray()],
			Responses = [Entry(certificate, issuer, Now.AddMinutes(-1), Now.AddHours(1))]
		}.Encode(responderKey);
	}

	private static byte[] CreateDefective(Defect defect, Certificate leaf, Authority issuer, Authority stranger)
	{
		return defect switch
		{
			Defect.Garbage => Garbage,

			// RFC 6960, Sec. 4.2.1: tryLater, without responseBytes.
			Defect.TryLater => Sequence([0x0A, 0x01, 0x03]),
			Defect.NotBasic => TestOcsp.Successful("1.3.6.1.5.5.7.48.1.99", [0x05, 0x00]),

			// A response for another certificate of the issuer, which has another serial number.
			Defect.OtherCertificate => Staple(issuer.Issue(new Template { Subject = Name("CN=Other"), SerialNumber = [0x02], SubjectPublicKeyInfo = leaf.PublicKeyInfo.Encoded.ToArray() }), issuer, Now.AddMinutes(-1), Now.AddHours(1)),
			Defect.UnauthorizedSigner => SignedByDelegatedResponder(leaf, issuer, [ExtendedKeyUsage("1.3.6.1.5.5.7.3.1")]),

			// A second ago, beyond which no clock skew widens the validity of the responder's certificate.
			Defect.ExpiredResponder => SignedByDelegatedResponder(leaf, issuer, [ExtendedKeyUsage(TestOcsp.OcspSigningOid)], Now.AddSeconds(-1)),

			// The responder ID names the issuer, whose key does not verify the signature.
			Defect.BadSignature => new TestOcsp.Basic
			{
				ResponderId = TestOcsp.ResponderByKey(issuer.Certificate),
				Responses = [Entry(leaf, issuer, Now.AddMinutes(-1), Now.AddHours(1))]
			}.Encode(stranger.Key),

			// Beyond the 5 minutes of clock skew at either end.
			Defect.Expired => Staple(leaf, issuer, Now.AddHours(-2), Now.AddMinutes(-6)),
			Defect.NotYetValid => Staple(leaf, issuer, Now.AddMinutes(6), Now.AddHours(1)),
			Defect.Unknown => Staple(leaf, issuer, Now.AddMinutes(-1), Now.AddHours(1), TestOcsp.UnknownStatus),
			_ => throw new UnreachableException()
		};
	}

	[Test]
	public async Task TheContextHasNoStapledResponseByDefault()
	{
		CertificateValidationContext context = new([SelfSignedP256()], CertificateUsage.ServerAuthentication);

		await Assert.That(context.StapledOcspResponse.IsEmpty).IsTrue();
	}

	[Test]
	public async Task TheContextKeepsACopyOfTheStapledResponse()
	{
		byte[] expected = [0x30, 0x03, 0x0A, 0x01, 0x00];
		byte[] response = [.. expected];
		byte[] buffer = [0xAA, .. expected, 0xBB];
		CertificateValidationContext whole = new([SelfSignedP256()], CertificateUsage.ServerAuthentication) { StapledOcspResponse = response };
		CertificateValidationContext slice = new([SelfSignedP256()], CertificateUsage.ServerAuthentication) { StapledOcspResponse = buffer.AsMemory(1, expected.Length) };

		response.AsSpan().Fill(0xFF);
		buffer.AsSpan().Fill(0xFF);

		using (Assert.Multiple())
		{
			await Assert.That(whole.StapledOcspResponse.ToArray()).IsEquivalentTo(expected, CollectionOrdering.Matching);
			await Assert.That(slice.StapledOcspResponse.ToArray()).IsEquivalentTo(expected, CollectionOrdering.Matching);
		}
	}

	[Test]
	public async Task AValidatorUsesNoStapledResponseAndNamesNoTrustAnchorsByDefault()
	{
		ICertificateValidator validator = new MinimalValidator();

		using (Assert.Multiple())
		{
			await Assert.That(validator.UsesStapledOcspResponse).IsFalse();
			await Assert.That(validator.TrustAnchorSubjects).IsEmpty();
		}
	}

	[Test]
	[Arguments(X509RevocationMode.Online, true)]
	[Arguments(X509RevocationMode.Offline, true)]
	[Arguments(X509RevocationMode.NoCheck, false)]
	public async Task UsesTheStapledResponseWhenItChecksRevocation(X509RevocationMode mode, bool expected)
	{
		using Authority root = Authority.CreateRoot();
		using TrustAnchorCertificateValidator validator = new([root.Certificate], SignatureKey.ImportSubjectPublicKeyInfo) { RevocationMode = mode };
		using TrustAnchorCertificateValidator byDefault = new([root.Certificate], SignatureKey.ImportSubjectPublicKeyInfo);
		ICertificateValidator contract = validator;

		using (Assert.Multiple())
		{
			await Assert.That(validator.UsesStapledOcspResponse).IsEqualTo(expected);
			await Assert.That(contract.UsesStapledOcspResponse).IsEqualTo(expected);
			await Assert.That(byDefault.UsesStapledOcspResponse).IsFalse();
		}
	}

	// In the order of the trust anchors, each name once, byte for byte: a name of another encoding is another name.
	[Test]
	public async Task TrustAnchorSubjectsNameEachTrustAnchorOnceInOrder()
	{
		using Authority first = Authority.CreateRoot("CN=First");
		using Authority second = Authority.CreateRoot("CN=Second");
		using Authority firstAgain = Authority.CreateRoot("CN=First");
		byte[] printable = Sequence(Tlv(0x31, Sequence(Oid("2.5.4.3"), Tlv(0x13, "Third"u8.ToArray()))));
		byte[] utf8 = Sequence(Tlv(0x31, Sequence(Oid("2.5.4.3"), Tlv(0x0C, "Third"u8.ToArray()))));
		using TrustAnchorCertificateValidator validator = new([second.Certificate, first.Certificate, firstAgain.Certificate, second.Certificate, CreateRoot(printable), CreateRoot(utf8)], SignatureKey.ImportSubjectPublicKeyInfo);
		IReadOnlyList<ReadOnlyMemory<byte>> subjects = validator.TrustAnchorSubjects;
		ICertificateValidator contract = validator;

		using (Assert.Multiple())
		{
			await Assert.That(subjects.Select(static subject => Convert.ToHexString(subject.Span))).IsEquivalentTo([Convert.ToHexString(second.Name), Convert.ToHexString(first.Name), Convert.ToHexString(printable), Convert.ToHexString(utf8)], CollectionOrdering.Matching);
			await Assert.That(contract.TrustAnchorSubjects).IsSameReferenceAs(subjects);
			await Assert.That(validator.TrustAnchorSubjects).IsSameReferenceAs(subjects);
			await Assert.That(subjects is IList<ReadOnlyMemory<byte>> { IsReadOnly: true }).IsTrue();
		}

		static Certificate CreateRoot(byte[] subject)
		{
			using EcdsaP256 key = EcdsaP256.GenerateKey();
			byte[] subjectPublicKeyInfo = ExportSubjectPublicKeyInfo(key);
			return Sign(new Template { Subject = subject, SubjectPublicKeyInfo = subjectPublicKeyInfo, Extensions = CaExtensions(subjectPublicKeyInfo) }, subject, key, SignatureAlgorithm.EcdsaSha256);
		}
	}

	// Threads that read the list for the first time at once all get the instance that the first to finish made.
	[Test]
	public async Task TrustAnchorSubjectsAreTheSameInstanceForConcurrentFirstCalls()
	{
		const int threads = 8;
		using Authority first = Authority.CreateRoot("CN=First");
		using Authority second = Authority.CreateRoot("CN=Second");
		using TrustAnchorCertificateValidator validator = new([first.Certificate, second.Certificate], SignatureKey.ImportSubjectPublicKeyInfo);
		using Barrier barrier = new(threads);

		Task<IReadOnlyList<ReadOnlyMemory<byte>>>[] reads = [.. Enumerable.Range(0, threads).Select(_ => Task.Factory.StartNew(() =>
		{
			barrier.SignalAndWait();
			return validator.TrustAnchorSubjects;
		}, CancellationToken.None, TaskCreationOptions.LongRunning, TaskScheduler.Default))];
		IReadOnlyList<ReadOnlyMemory<byte>>[] subjects = await Task.WhenAll(reads);

		using (Assert.Multiple())
		{
			foreach (IReadOnlyList<ReadOnlyMemory<byte>> list in subjects)
			{
				await Assert.That(list).IsSameReferenceAs(subjects[0]);
			}

			await Assert.That(validator.TrustAnchorSubjects).IsSameReferenceAs(subjects[0]);
			await Assert.That(subjects[0].Count).IsEqualTo(2);
		}
	}

	// The peer's own sources revoke it, but are not asked, so the good stapled response accepts it, and the intermediate certificate is checked as before.
	// A CRL that the caller gives and that revokes it still decides over the good response, which the peer could have obtained before the revocation.
	[Test]
	public async Task AGoodStapledResponseDecidesWithoutThePeersOwnSources()
	{
		using Authority root = Authority.CreateRoot();
		using Authority intermediate = root.CreateIntermediate(more: [Aia(ocsp: [IssuerOcspUri])]);
		Certificate leaf = intermediate.IssueLeaf(more: [Aia(ocsp: [OcspUri]), Cdp(CrlUri)]);
		FakeRetriever retriever = new()
		{
			Responder = Ocsp(leaf, intermediate, TestOcsp.Revoked(Now.AddHours(-1))),
			[CrlUri] = EncodeCrl(intermediate, leaf)
		};
		retriever.ByHost.Add(new Uri(IssuerOcspUri).Host, Ocsp(intermediate.Certificate, root, TestOcsp.Good));
		using TrustAnchorCertificateValidator validator = new([root.Certificate], SignatureKey.ImportSubjectPublicKeyInfo)
		{
			Retriever = retriever,
			RevocationMode = X509RevocationMode.Online
		};
		using TrustAnchorCertificateValidator revokedByTheCaller = new([root.Certificate], SignatureKey.ImportSubjectPublicKeyInfo)
		{
			RevocationMode = X509RevocationMode.Offline,
			RevocationFlag = X509RevocationFlag.EndCertificateOnly,
			RevocationLists = [DecodeCrl(intermediate, leaf)]
		};

		CertificateValidationResult issuerSigned = await Validate(validator, Ocsp(leaf, intermediate, TestOcsp.Good), leaf, intermediate.Certificate);
		int requests = retriever.Requests.Count;
		CertificateValidationResult delegated = await Validate(validator, SignedByDelegatedResponder(leaf, intermediate, [ExtendedKeyUsage(TestOcsp.OcspSigningOid)]), leaf, intermediate.Certificate);
		CertificateValidationResult revoked = await Validate(revokedByTheCaller, Ocsp(leaf, intermediate, TestOcsp.Good), leaf, intermediate.Certificate);

		using (Assert.Multiple())
		{
			await AssertValid(issuerSigned, leaf, intermediate.Certificate, root.Certificate);
			await AssertValid(delegated, leaf, intermediate.Certificate, root.Certificate);

			// Only the intermediate certificate's responder is asked, once, as the second validation finds its response in the cache.
			await Assert.That(requests).IsEqualTo(1);
			await Assert.That(retriever.Requests.Select(static request => request.Uri.Host)).IsEquivalentTo([new Uri(IssuerOcspUri).Host]);

			await AssertInvalid(revoked, [CertificateValidationError.Revoked], CertificatePathEnd.TrustAnchor, leaf, intermediate.Certificate, root.Certificate);
		}
	}

	// A CRL that the caller gives and that revokes the certificate decides before a stapled response that is not acceptable, which is then not looked at.
	[Test]
	public async Task ACrlThatTheCallerGivesRevokesBeforeAStapledResponseThatIsNotAcceptable()
	{
		using Authority root = Authority.CreateRoot();
		Certificate leaf = root.IssueLeaf();
		using TrustAnchorCertificateValidator validator = new([root.Certificate], SignatureKey.ImportSubjectPublicKeyInfo)
		{
			RevocationMode = X509RevocationMode.Offline,
			RevocationLists = [DecodeCrl(root, leaf)]
		};

		await AssertInvalid(await Validate(validator, Garbage, leaf), [CertificateValidationError.Revoked], CertificatePathEnd.TrustAnchor, leaf, root.Certificate);
	}

	// RFC 9608, Sec. 4: a certificate that exempts itself asks no source, so a CRL that the caller gives and that revokes it has no effect, and the good stapled response, which is still checked, accepts it.
	[Test]
	[Arguments(TestOcsp.NoCheckOid)]
	[Arguments(NoRevAvailOid)]
	public async Task ACrlThatTheCallerGivesDoesNotRevokeACertificateThatExemptsItselfWithAStapledResponse(string oid)
	{
		using Authority root = Authority.CreateRoot();
		Certificate leaf = root.IssueLeaf(more: [NullExtension(oid)]);
		using TrustAnchorCertificateValidator validator = new([root.Certificate], SignatureKey.ImportSubjectPublicKeyInfo)
		{
			RevocationMode = X509RevocationMode.Offline,
			RevocationLists = [DecodeCrl(root, leaf)]
		};

		using (Assert.Multiple())
		{
			await AssertValid(await Validate(validator, Ocsp(leaf, root, TestOcsp.Good), leaf), leaf, root.Certificate);
			await AssertInvalid(await Validate(validator, Garbage, leaf), [CertificateValidationError.InvalidOcspResponse], CertificatePathEnd.TrustAnchor, leaf, root.Certificate);
		}
	}

	// A response longer than 64 KiB, the limit of a retrieved one, is not decoded; one of exactly 64 KiB is, and here does not decode.
	[Test]
	public async Task BoundsTheLengthOfAStapledResponse()
	{
		using Authority root = Authority.CreateRoot();
		Certificate leaf = root.IssueLeaf();
		using TrustAnchorCertificateValidator validator = new([root.Certificate], SignatureKey.ImportSubjectPublicKeyInfo) { RevocationMode = X509RevocationMode.Offline };
		byte[] good = Ocsp(leaf, root, TestOcsp.Good);
		byte[] tooLong = new byte[(64 << 10) + 1];
		byte[] longest = new byte[64 << 10];
		good.CopyTo(tooLong, 0);
		good.CopyTo(longest, 0);

		CertificateValidationResult tooLongResult = await Validate(validator, tooLong, leaf);
		CertificateValidationResult longestResult = await Validate(validator, longest, leaf);

		using (Assert.Multiple())
		{
			await AssertInvalid(tooLongResult, [CertificateValidationError.InvalidOcspResponse], CertificatePathEnd.TrustAnchor, leaf, root.Certificate);
			await Assert.That(tooLongResult.Message).Contains("longer than 64 KiB");
			await AssertInvalid(longestResult, [CertificateValidationError.InvalidOcspResponse], CertificatePathEnd.TrustAnchor, leaf, root.Certificate);
			await Assert.That(longestResult.Message).Contains("does not decode").And.DoesNotContain("KiB");
			await AssertValid(await Validate(validator, good, leaf), leaf, root.Certificate);
		}
	}

	// The keys of the peer's certificates and of a delegated responder are disposed at the end of the validation, whatever the response says; only those of the trust anchors remain.
	[Test]
	public async Task DisposesTheKeysOfAValidationWithAStapledResponse()
	{
		using Authority root = Authority.CreateRoot();
		using Authority intermediate = root.CreateIntermediate();
		Certificate leaf = intermediate.IssueLeaf();
		KeyLog log = new();
		using TrustAnchorCertificateValidator validator = new([root.Certificate], log.Import)
		{
			RevocationMode = X509RevocationMode.Offline,
			RevocationFlag = X509RevocationFlag.EndCertificateOnly
		};
		int anchorKeys = log.Imports;

		CertificateValidationResult issuerSigned = await Validate(validator, Ocsp(leaf, intermediate, TestOcsp.Good), leaf, intermediate.Certificate);
		CertificateValidationResult delegated = await Validate(validator, SignedByDelegatedResponder(leaf, intermediate, [ExtendedKeyUsage(TestOcsp.OcspSigningOid)]), leaf, intermediate.Certificate);
		CertificateValidationResult revoked = await Validate(validator, Ocsp(leaf, intermediate, TestOcsp.Revoked(Now.AddHours(-1))), leaf, intermediate.Certificate);
		CertificateValidationResult garbage = await Validate(validator, Garbage, leaf, intermediate.Certificate);
		int importsBeforeDisposal = log.Imports;
		int disposalsBeforeDisposal = log.Disposals;
		// ReSharper disable once DisposeOnUsingVariable
		validator.Dispose();

		using (Assert.Multiple())
		{
			await AssertValid(issuerSigned, leaf, intermediate.Certificate, root.Certificate);
			await AssertValid(delegated, leaf, intermediate.Certificate, root.Certificate);
			await AssertInvalid(revoked, [CertificateValidationError.Revoked], CertificatePathEnd.TrustAnchor, leaf, intermediate.Certificate, root.Certificate);
			await AssertInvalid(garbage, [CertificateValidationError.InvalidOcspResponse], CertificatePathEnd.TrustAnchor, leaf, intermediate.Certificate, root.Certificate);
			await Assert.That(anchorKeys).IsEqualTo(1);
			await Assert.That(importsBeforeDisposal).IsGreaterThan(anchorKeys);
			await Assert.That(disposalsBeforeDisposal).IsEqualTo(importsBeforeDisposal - anchorKeys);
			await Assert.That(log.Disposals).IsEqualTo(log.Imports);
		}
	}

	// A stapled response that is not accepted fails the path at once, so the certificates above are not checked: the intermediate certificate, which a CRL that the caller gives revokes, does not make it Revoked.
	// The CRLs that the caller gives do not revoke the peer's certificate, so they do not decide before the response.
	[Test]
	public async Task AStapledResponseThatIsNotAcceptableEndsTheChecksOfThePath()
	{
		using Authority root = Authority.CreateRoot();
		using Authority intermediate = root.CreateIntermediate();
		Certificate leaf = intermediate.IssueLeaf();
		using TrustAnchorCertificateValidator validator = new([root.Certificate], SignatureKey.ImportSubjectPublicKeyInfo)
		{
			RevocationMode = X509RevocationMode.Offline,
			RevocationLists = [DecodeCrl(root, intermediate.Certificate), DecodeCrl(intermediate)]
		};

		using (Assert.Multiple())
		{
			await AssertInvalid(await Validate(validator, Garbage, leaf, intermediate.Certificate), [CertificateValidationError.InvalidOcspResponse], CertificatePathEnd.TrustAnchor, leaf, intermediate.Certificate, root.Certificate);
			await AssertInvalid(await Validate(validator, Ocsp(leaf, intermediate, TestOcsp.Good), leaf, intermediate.Certificate), [CertificateValidationError.Revoked], CertificatePathEnd.TrustAnchor, leaf, intermediate.Certificate, root.Certificate);
		}
	}

	[Test]
	public async Task ARevokedStapledResponseRevokes()
	{
		using Authority root = Authority.CreateRoot();
		Certificate leaf = root.IssueLeaf(more: [Aia(ocsp: [OcspUri]), Cdp(CrlUri)]);
		FakeRetriever retriever = new()
		{
			Responder = Ocsp(leaf, root, TestOcsp.Good),
			[CrlUri] = EncodeCrl(root)
		};
		using TrustAnchorCertificateValidator validator = new([root.Certificate], SignatureKey.ImportSubjectPublicKeyInfo)
		{
			Retriever = retriever,
			RevocationMode = X509RevocationMode.Online,
			RevocationLists = [DecodeCrl(root)]
		};

		CertificateValidationResult result = await Validate(validator, Ocsp(leaf, root, TestOcsp.Revoked(Now.AddHours(-3), reason: 1)), leaf);

		using (Assert.Multiple())
		{
			await AssertInvalid(result, [CertificateValidationError.Revoked], CertificatePathEnd.TrustAnchor, leaf, root.Certificate);
			await Assert.That(result.Message).Contains("KeyCompromise");
			await Assert.That(retriever.Requests).IsEmpty();
		}
	}

	// Every other source says good, and an unknown status would be accepted, so only the stapled response fails the path: the CRL that the caller gives does not stand in for it, and the peer's own sources are not asked.
	[Test]
	[Arguments(Defect.Garbage, "does not decode")]
	[Arguments(Defect.TryLater, "answered TryLater")]
	[Arguments(Defect.NotBasic, "not id-pkix-ocsp-basic")]
	[Arguments(Defect.OtherCertificate, "no status for the certificate")]
	[Arguments(Defect.UnauthorizedSigner, "does not assert id-kp-OCSPSigning")]
	[Arguments(Defect.ExpiredResponder, "not valid at the time")]
	[Arguments(Defect.BadSignature, "does not verify")]
	[Arguments(Defect.Expired, "has expired")]
	[Arguments(Defect.NotYetValid, "not yet valid")]
	[Arguments(Defect.Unknown, "does not know the certificate")]
	public async Task RefusesAStapledResponseThatIsNotAcceptable(Defect defect, string detail)
	{
		using Authority root = Authority.CreateRoot();
		using Authority stranger = Authority.CreateRoot("CN=Stranger");
		Certificate leaf = root.IssueLeaf(more: [Aia(ocsp: [OcspUri]), Cdp(CrlUri)]);
		byte[] stapled = CreateDefective(defect, leaf, root, stranger);
		FakeRetriever retriever = new()
		{
			Responder = Ocsp(leaf, root, TestOcsp.Good),
			[CrlUri] = EncodeCrl(root)
		};
		using TrustAnchorCertificateValidator online = new([root.Certificate], SignatureKey.ImportSubjectPublicKeyInfo)
		{
			Retriever = retriever,
			RevocationMode = X509RevocationMode.Online,
			RevocationLists = [DecodeCrl(root)],
			IgnoreRevocationUnknown = true
		};
		using TrustAnchorCertificateValidator offline = new([root.Certificate], SignatureKey.ImportSubjectPublicKeyInfo)
		{
			RevocationMode = X509RevocationMode.Offline,
			RevocationLists = [DecodeCrl(root)],
			IgnoreRevocationUnknown = true
		};

		CertificateValidationResult onlineResult = await Validate(online, stapled, leaf);
		CertificateValidationResult offlineResult = await Validate(offline, stapled, leaf);

		using (Assert.Multiple())
		{
			await AssertInvalid(onlineResult, [CertificateValidationError.InvalidOcspResponse], CertificatePathEnd.TrustAnchor, leaf, root.Certificate);
			await Assert.That(onlineResult.Message).Contains("stapled").And.Contains(detail);
			await Assert.That(retriever.Requests).IsEmpty();
			await AssertInvalid(offlineResult, [CertificateValidationError.InvalidOcspResponse], CertificatePathEnd.TrustAnchor, leaf, root.Certificate);

			// Without the stapled response, the CRL accepts the certificate.
			await AssertValid(await Validate(offline, default, leaf), leaf, root.Certificate);
		}
	}

	// The 5 minutes of clock skew of any response apply at each end.
	[Test]
	public async Task AcceptsAStapledResponseWithinTheClockSkew()
	{
		using Authority root = Authority.CreateRoot();
		Certificate leaf = root.IssueLeaf();
		using TrustAnchorCertificateValidator validator = new([root.Certificate], SignatureKey.ImportSubjectPublicKeyInfo) { RevocationMode = X509RevocationMode.Offline };

		using (Assert.Multiple())
		{
			await AssertValid(await Validate(validator, Staple(leaf, root, Now.AddMinutes(4), Now.AddHours(1)), leaf), leaf, root.Certificate);
			await AssertValid(await Validate(validator, Staple(leaf, root, Now.AddHours(-2), Now.AddMinutes(-4)), leaf), leaf, root.Certificate);
		}
	}

	// Of several responses for the certificate, the most severe of those that are current stands, as for any response.
	[Test]
	public async Task TheMostSevereCurrentResponseStands()
	{
		using Authority root = Authority.CreateRoot();
		Certificate leaf = root.IssueLeaf();
		byte[] good = Entry(leaf, root, Now.AddMinutes(-1), Now.AddHours(1));
		byte[] revoked = Entry(leaf, root, Now.AddMinutes(-1), Now.AddHours(1), TestOcsp.Revoked(Now.AddHours(-1)));
		byte[] staleRevoked = Entry(leaf, root, Now.AddHours(-3), Now.AddHours(-2), TestOcsp.Revoked(Now.AddHours(-4)));
		using TrustAnchorCertificateValidator validator = new([root.Certificate], SignatureKey.ImportSubjectPublicKeyInfo) { RevocationMode = X509RevocationMode.Offline };

		using (Assert.Multiple())
		{
			await AssertInvalid(await Validate(validator, Responses(good, revoked), leaf), [CertificateValidationError.Revoked], CertificatePathEnd.TrustAnchor, leaf, root.Certificate);
			await AssertValid(await Validate(validator, Responses(staleRevoked, good), leaf), leaf, root.Certificate);
		}

		byte[] Responses(params byte[][] entries)
		{
			return new TestOcsp.Basic
			{
				ResponderId = TestOcsp.ResponderByKey(root.Certificate),
				Responses = entries
			}.Encode(root.Key);
		}
	}

	[Test]
	public async Task NoCheckIgnoresTheStapledResponse()
	{
		using Authority root = Authority.CreateRoot();
		Certificate leaf = root.IssueLeaf(more: [Aia(ocsp: [OcspUri]), Cdp(CrlUri)]);
		FakeRetriever retriever = new();
		using TrustAnchorCertificateValidator validator = new([root.Certificate], SignatureKey.ImportSubjectPublicKeyInfo);
		using TrustAnchorCertificateValidator retrieving = new([root.Certificate], SignatureKey.ImportSubjectPublicKeyInfo) { Retriever = retriever };

		using (Assert.Multiple())
		{
			foreach (byte[] stapled in (byte[][])[Garbage, Ocsp(leaf, root, TestOcsp.Revoked(Now.AddHours(-1)))])
			{
				await AssertValid(await Validate(validator, stapled, leaf), leaf, root.Certificate);
				await AssertValid(await Validate(retrieving, stapled, leaf), leaf, root.Certificate);
			}

			await Assert.That(retriever.Requests).IsEmpty();
		}
	}

	// A trust anchor presented as the peer's certificate is a path of its own, whose status is not checked.
	[Test]
	[Arguments(X509RevocationMode.Offline)]
	[Arguments(X509RevocationMode.Online)]
	public async Task APeerCertificateThatIsATrustAnchorIgnoresTheStapledResponse(X509RevocationMode mode)
	{
		using Authority root = Authority.CreateRoot();
		Certificate pinned = root.IssueLeaf(more: [Aia(ocsp: [OcspUri]), Cdp(CrlUri)]);
		FakeRetriever retriever = new();
		using TrustAnchorCertificateValidator validator = new([root.Certificate, pinned], SignatureKey.ImportSubjectPublicKeyInfo)
		{
			Retriever = retriever,
			RevocationMode = mode
		};

		using (Assert.Multiple())
		{
			await AssertValid(await Validate(validator, Garbage, pinned), pinned);
			await AssertValid(await Validate(validator, Ocsp(pinned, root, TestOcsp.Revoked(Now.AddHours(-1))), pinned), pinned);
			await Assert.That(retriever.Requests).IsEmpty();
		}
	}

	// A stapled response needs no network, so it settles the peer's certificate offline, where no CRL that the caller gives does.
	[Test]
	public async Task OfflineChecksTheStapledResponseOfTheEndCertificate()
	{
		using Authority root = Authority.CreateRoot();
		using Authority intermediate = root.CreateIntermediate();
		Certificate leaf = intermediate.IssueLeaf(more: [Aia(ocsp: [OcspUri]), Cdp(CrlUri)]);
		using TrustAnchorCertificateValidator validator = new([root.Certificate], SignatureKey.ImportSubjectPublicKeyInfo)
		{
			RevocationMode = X509RevocationMode.Offline,
			RevocationFlag = X509RevocationFlag.EndCertificateOnly
		};

		ValueTask<CertificateValidationResult> stapled = validator.ValidateAsync(new CertificateValidationContext([leaf, intermediate.Certificate], CertificateUsage.ServerAuthentication)
		{
			StapledOcspResponse = Ocsp(leaf, intermediate, TestOcsp.Good),
			TimeProvider = new FixedTimeProvider(Now)
		});

		using (Assert.Multiple())
		{
			await Assert.That(stapled.IsCompletedSuccessfully).IsTrue();
			await AssertValid(await stapled, leaf, intermediate.Certificate, root.Certificate);
			await AssertInvalid(await Validate(validator, default, leaf, intermediate.Certificate), [CertificateValidationError.RevocationUnknown], CertificatePathEnd.TrustAnchor, leaf, intermediate.Certificate, root.Certificate);
		}
	}

	// RFC 6066, Sec. 8: a client that asked for the response must check it, though RFC 9608, Sec. 4, skips the other sources of such a certificate.
	[Test]
	[Arguments(TestOcsp.NoCheckOid)]
	[Arguments(NoRevAvailOid)]
	public async Task ChecksTheStapledResponseOfACertificateThatExemptsItself(string oid)
	{
		using Authority root = Authority.CreateRoot();
		Certificate leaf = root.IssueLeaf(more: [NullExtension(oid)]);
		using TrustAnchorCertificateValidator validator = new([root.Certificate], SignatureKey.ImportSubjectPublicKeyInfo) { RevocationMode = X509RevocationMode.Offline };

		using (Assert.Multiple())
		{
			await AssertValid(await Validate(validator, default, leaf), leaf, root.Certificate);
			await AssertValid(await Validate(validator, Ocsp(leaf, root, TestOcsp.Good), leaf), leaf, root.Certificate);
			await AssertInvalid(await Validate(validator, Garbage, leaf), [CertificateValidationError.InvalidOcspResponse], CertificatePathEnd.TrustAnchor, leaf, root.Certificate);
			await AssertInvalid(await Validate(validator, Ocsp(leaf, root, TestOcsp.UnknownStatus), leaf), [CertificateValidationError.InvalidOcspResponse], CertificatePathEnd.TrustAnchor, leaf, root.Certificate);
			await AssertInvalid(await Validate(validator, Ocsp(leaf, root, TestOcsp.Revoked(Now.AddHours(-1))), leaf), [CertificateValidationError.Revoked], CertificatePathEnd.TrustAnchor, leaf, root.Certificate);
		}
	}

	// Two candidate issuers of one name whose keys both verify the peer's certificate, as an importer that stands the issuer's key in for the impostor's makes them, so that only the CertID of the stapled response, which hashes the issuer's key, tells them apart.
	// The impostor has the issuer's key identifier and is presented first, so the search tries it first.
	[Test]
	public async Task AStapledResponseForAnotherIssuerGivesWayToTheIssuerThatItNames()
	{
		using Authority root = Authority.CreateRoot();
		using Authority issuer = root.CreateIntermediate();
		using EcdsaP256 impostorKey = EcdsaP256.GenerateKey();
		byte[] impostorKeyInfo = ExportSubjectPublicKeyInfo(impostorKey);
		byte[] issuerKeyInfo = issuer.Certificate.PublicKeyInfo.Encoded.ToArray();
		Certificate impostor = root.Issue
		(
			new Template
			{
				Subject = issuer.Name,
				SerialNumber = [0x02],
				SubjectPublicKeyInfo = impostorKeyInfo,
				Extensions = [BasicConstraints(true), KeyUsage(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign), SubjectKeyIdentifier(issuer.KeyIdentifier), AuthorityKeyIdentifier(root.KeyIdentifier)]
			}
		);
		Certificate leaf = issuer.IssueLeaf();
		byte[] stapled = Ocsp(leaf, issuer, TestOcsp.Good);
		using TrustAnchorCertificateValidator noCheck = Create(X509RevocationMode.NoCheck, X509RevocationFlag.EndCertificateOnly);
		using TrustAnchorCertificateValidator endOnly = Create(X509RevocationMode.Offline, X509RevocationFlag.EndCertificateOnly);
		using TrustAnchorCertificateValidator unknownAbove = Create(X509RevocationMode.Offline, X509RevocationFlag.ExcludeRoot);
		using TrustAnchorCertificateValidator revokedAbove = Create(X509RevocationMode.Offline, X509RevocationFlag.ExcludeRoot, DecodeCrl(root, issuer.Certificate));

		using (Assert.Multiple())
		{
			// Without the revocation check, the first path goes through the impostor.
			await AssertValid(await Validate(noCheck, stapled, leaf, impostor, issuer.Certificate), leaf, impostor, root.Certificate);

			// The response names the issuer, so the edge to the impostor fails and the search goes on to the issuer.
			await AssertValid(await Validate(endOnly, stapled, leaf, impostor, issuer.Certificate), leaf, issuer.Certificate, root.Certificate);

			// Without the issuer every path fails, and the result reports the stapled response.
			await AssertInvalid(await Validate(endOnly, stapled, leaf, impostor), [CertificateValidationError.InvalidOcspResponse], CertificatePathEnd.TrustAnchor, leaf, impostor, root.Certificate);

			// A path whose stapled response is not accepted is reported after one that got past the response, with a status that is unknown or revoked above it.
			await AssertInvalid(await Validate(unknownAbove, stapled, leaf, impostor, issuer.Certificate), [CertificateValidationError.RevocationUnknown], CertificatePathEnd.TrustAnchor, leaf, issuer.Certificate, root.Certificate);
			await AssertInvalid(await Validate(revokedAbove, stapled, leaf, impostor, issuer.Certificate), [CertificateValidationError.Revoked], CertificatePathEnd.TrustAnchor, leaf, issuer.Certificate, root.Certificate);
		}

		TrustAnchorCertificateValidator Create(X509RevocationMode mode, X509RevocationFlag flag, params CertificateRevocationList[] lists)
		{
			return new TrustAnchorCertificateValidator([root.Certificate], subjectPublicKeyInfo => SignatureKey.ImportSubjectPublicKeyInfo(subjectPublicKeyInfo.SequenceEqual(impostorKeyInfo) ? issuerKeyInfo : subjectPublicKeyInfo))
			{
				RevocationMode = mode,
				RevocationFlag = flag,
				RevocationLists = lists
			};
		}
	}

	private sealed class MinimalValidator : ICertificateValidator
	{
		public ValueTask<CertificateValidationResult> ValidateAsync(CertificateValidationContext context, CancellationToken cancellationToken = default)
		{
			return ValueTask.FromResult(CertificateValidationResult.Valid);
		}
	}
}
