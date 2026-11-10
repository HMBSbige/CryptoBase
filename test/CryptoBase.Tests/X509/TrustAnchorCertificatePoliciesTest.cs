using CryptoBase.Abstractions.Signatures;
using CryptoBase.Signatures;
using CryptoBase.Signatures.Ecdsa;
using CryptoBase.X509;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Text;
using static CryptoBase.Tests.Signatures.SignatureTestUtils;
using static CryptoBase.Tests.TestUtils;
using static CryptoBase.Tests.X509.TestPki;
using static CryptoBase.Tests.X509.TrustAnchorCertificateValidatorTest;
using static CryptoBase.Tests.X509.X509TestUtils;

namespace CryptoBase.Tests.X509;

[SuppressMessage("ReSharper", "AccessToDisposedClosure")]
public class TrustAnchorCertificatePoliciesTest
{
	private const string P1 = "1.3.6.1.4.1.55738.77.1";
	private const string P2 = "1.3.6.1.4.1.55738.77.2";
	private const string P3 = "1.3.6.1.4.1.55738.77.3";

	private static readonly CertificateValidationError[] NotValid = [CertificateValidationError.NotValidForUsage];

	private static async Task<CertificateValidationResult> ValidateWith(Authority root, Certificate[] presented, string[]? initial = null, bool explicitPolicy = false, bool inhibitMapping = false, bool inhibitAny = false)
	{
		using TrustAnchorCertificateValidator validator = new([root.Certificate], SignatureKey.ImportSubjectPublicKeyInfo) { InitialPolicies = initial ?? [AnyPolicyOid], RequireExplicitPolicy = explicitPolicy, InhibitPolicyMapping = inhibitMapping, InhibitAnyPolicy = inhibitAny };
		return await validator.ValidateAsync(new CertificateValidationContext(presented, CertificateUsage.ServerAuthentication));
	}

	private static Task AssertRejected(CertificateValidationResult result, params Certificate[] path)
	{
		return AssertInvalid(result, NotValid, CertificatePathEnd.TrustAnchor, path);
	}

	// RFC 5280, Sec. 6.1.5: without a requirement for an explicit policy, the policies do not matter, even if they have no intersection; a requirement takes a policy of every certificate.
	[Test]
	public async Task RequiresAnExplicitPolicyOnlyWhenAsked()
	{
		using Authority root = Authority.CreateRoot();
		using Authority issuing = root.CreateIntermediate(more: [CertificatePolicies(P1)]);
		Certificate disjoint = issuing.IssueLeaf(more: [CertificatePolicies(P2)]);
		Certificate same = issuing.IssueLeaf(more: [CertificatePolicies(P1)]);
		using Authority noPolicies = root.CreateIntermediate("CN=No policies");
		Certificate leafWithoutPolicies = noPolicies.IssueLeaf();

		using (Assert.Multiple())
		{
			await AssertValid(await ValidateWith(root, [disjoint, issuing.Certificate]), disjoint, issuing.Certificate, root.Certificate);
			await AssertRejected(await ValidateWith(root, [disjoint, issuing.Certificate], explicitPolicy: true), disjoint, issuing.Certificate, root.Certificate);
			await AssertValid(await ValidateWith(root, [same, issuing.Certificate], explicitPolicy: true), same, issuing.Certificate, root.Certificate);
			await AssertValid(await ValidateWith(root, [leafWithoutPolicies, noPolicies.Certificate]), leafWithoutPolicies, noPolicies.Certificate, root.Certificate);
			await AssertRejected(await ValidateWith(root, [leafWithoutPolicies, noPolicies.Certificate], explicitPolicy: true), leafWithoutPolicies, noPolicies.Certificate, root.Certificate);
		}
	}

	// RFC 5280, Sec. 6.1.5: the initial policy set narrows the result of a path that requires an explicit policy, and of no other.
	[Test]
	public async Task TheInitialPoliciesNarrowARequiredPolicy()
	{
		using Authority root = Authority.CreateRoot();
		using Authority issuing = root.CreateIntermediate(more: [CertificatePolicies(P1, P2)]);
		Certificate leaf = issuing.IssueLeaf(more: [CertificatePolicies(P1, P2)]);

		using (Assert.Multiple())
		{
			await AssertValid(await ValidateWith(root, [leaf, issuing.Certificate], [P2], explicitPolicy: true), leaf, issuing.Certificate, root.Certificate);
			await AssertValid(await ValidateWith(root, [leaf, issuing.Certificate], [P2, P3], explicitPolicy: true), leaf, issuing.Certificate, root.Certificate);
			await AssertRejected(await ValidateWith(root, [leaf, issuing.Certificate], [P3], explicitPolicy: true), leaf, issuing.Certificate, root.Certificate);
			await AssertValid(await ValidateWith(root, [leaf, issuing.Certificate], [P3]), leaf, issuing.Certificate, root.Certificate);
			await AssertValid(await ValidateWith(root, [leaf, issuing.Certificate], [P3, AnyPolicyOid], explicitPolicy: true), leaf, issuing.Certificate, root.Certificate);
		}
	}

	// RFC 5280, Sec. 6.1.3 (d): anyPolicy in a certificate stands for the expected policies of the depth before it, and a policy below anyPolicy is the policy of the path.
	[Test]
	public async Task AnyPolicyPassesOnThePoliciesAboveIt()
	{
		using Authority root = Authority.CreateRoot();
		using Authority any = root.CreateIntermediate(more: [CertificatePolicies(AnyPolicyOid)]);
		Certificate leafP1 = any.IssueLeaf(more: [CertificatePolicies(P1)]);
		Certificate leafAny = any.IssueLeaf(more: [CertificatePolicies(AnyPolicyOid)]);
		using Authority p1 = root.CreateIntermediate("CN=P1", more: [CertificatePolicies(P1)]);
		using Authority anyBelowP1 = p1.CreateIntermediate("CN=Any below P1", more: [CertificatePolicies(AnyPolicyOid)]);
		Certificate p1Leaf = anyBelowP1.IssueLeaf(more: [CertificatePolicies(P1)]);
		Certificate p2Leaf = anyBelowP1.IssueLeaf(more: [CertificatePolicies(P2)]);

		using (Assert.Multiple())
		{
			await AssertValid(await ValidateWith(root, [leafP1, any.Certificate], [P1], explicitPolicy: true), leafP1, any.Certificate, root.Certificate);
			await AssertRejected(await ValidateWith(root, [leafP1, any.Certificate], [P2], explicitPolicy: true), leafP1, any.Certificate, root.Certificate);
			await AssertValid(await ValidateWith(root, [leafAny, any.Certificate], [P1], explicitPolicy: true), leafAny, any.Certificate, root.Certificate);
			await AssertValid(await ValidateWith(root, [p1Leaf, anyBelowP1.Certificate, p1.Certificate], [P1], explicitPolicy: true), p1Leaf, anyBelowP1.Certificate, p1.Certificate, root.Certificate);
			await AssertRejected(await ValidateWith(root, [p2Leaf, anyBelowP1.Certificate, p1.Certificate], explicitPolicy: true), p2Leaf, anyBelowP1.Certificate, p1.Certificate, root.Certificate);
		}
	}

	// RFC 5280, Sec. 6.1.4 (b): a mapping replaces the expected policy of its issuer policy, one issuer policy can map to several, and the issuer policy is the policy of the path.
	[Test]
	public async Task FollowsPolicyMappings()
	{
		using Authority root = Authority.CreateRoot();
		using Authority mapping = root.CreateIntermediate(more: [CertificatePolicies(P1), PolicyMappings((P1, P2))]);
		Certificate mapped = mapping.IssueLeaf(more: [CertificatePolicies(P2)]);
		Certificate unmapped = mapping.IssueLeaf(more: [CertificatePolicies(P1)]);
		using Authority split = root.CreateIntermediate("CN=Split", more: [CertificatePolicies(P1), PolicyMappings((P1, P2), (P1, P3))]);
		Certificate splitLeaf = split.IssueLeaf(more: [CertificatePolicies(P3)]);
		using Authority keeping = root.CreateIntermediate("CN=Keeping", more: [CertificatePolicies(P1), PolicyMappings((P1, P1), (P1, P2))]);
		Certificate keptLeaf = keeping.IssueLeaf(more: [CertificatePolicies(P1)]);

		using (Assert.Multiple())
		{
			await AssertValid(await ValidateWith(root, [mapped, mapping.Certificate], [P1], explicitPolicy: true), mapped, mapping.Certificate, root.Certificate);
			await AssertRejected(await ValidateWith(root, [mapped, mapping.Certificate], [P2], explicitPolicy: true), mapped, mapping.Certificate, root.Certificate);
			await AssertRejected(await ValidateWith(root, [unmapped, mapping.Certificate], explicitPolicy: true), unmapped, mapping.Certificate, root.Certificate);
			await AssertValid(await ValidateWith(root, [splitLeaf, split.Certificate], [P1], explicitPolicy: true), splitLeaf, split.Certificate, root.Certificate);
			await AssertValid(await ValidateWith(root, [keptLeaf, keeping.Certificate], [P1], explicitPolicy: true), keptLeaf, keeping.Certificate, root.Certificate);
		}
	}

	// RFC 5280, Sec. 6.1.4 (b)(2): a mapping of a policy that only anyPolicy stands for creates the policy, as a child of anyPolicy.
	[Test]
	public async Task MapsThePoliciesThatAnyPolicyStandsFor()
	{
		using Authority root = Authority.CreateRoot();
		using Authority any = root.CreateIntermediate(more: [CertificatePolicies(AnyPolicyOid), PolicyMappings((P1, P2))]);
		Certificate unmappedLeaf = any.IssueLeaf(more: [CertificatePolicies(P1)]);
		Certificate mappedLeaf = any.IssueLeaf(more: [CertificatePolicies(P2)]);
		using Authority p1 = root.CreateIntermediate("CN=P1", more: [CertificatePolicies(P1)]);
		using Authority mapsBelow = p1.CreateIntermediate("CN=Mapping", more: [CertificatePolicies(AnyPolicyOid), PolicyMappings((P1, P2))]);
		Certificate belowP2 = mapsBelow.IssueLeaf(more: [CertificatePolicies(P2)]);
		Certificate belowP1 = mapsBelow.IssueLeaf(more: [CertificatePolicies(P1)]);

		using (Assert.Multiple())
		{
			await AssertValid(await ValidateWith(root, [unmappedLeaf, any.Certificate], [P1], explicitPolicy: true), unmappedLeaf, any.Certificate, root.Certificate);
			await AssertValid(await ValidateWith(root, [mappedLeaf, any.Certificate], [P1], explicitPolicy: true), mappedLeaf, any.Certificate, root.Certificate);
			await AssertRejected(await ValidateWith(root, [mappedLeaf, any.Certificate], [P3], explicitPolicy: true), mappedLeaf, any.Certificate, root.Certificate);
			await AssertValid(await ValidateWith(root, [belowP2, mapsBelow.Certificate, p1.Certificate], [P1], explicitPolicy: true), belowP2, mapsBelow.Certificate, p1.Certificate, root.Certificate);
			await AssertRejected(await ValidateWith(root, [belowP1, mapsBelow.Certificate, p1.Certificate], explicitPolicy: true), belowP1, mapsBelow.Certificate, p1.Certificate, root.Certificate);
		}
	}

	// RFC 5280, Secs. 6.1.1 (e) and 6.1.4 (b)(3), (h) and (i): policy_mapping counts the certificates before it reaches zero, where mappings no longer apply and remove their issuer policy.
	[Test]
	public async Task InhibitsPolicyMapping()
	{
		using Authority root = Authority.CreateRoot();
		using Authority inhibited = root.CreateIntermediate(more: [CertificatePolicies(P1), PolicyConstraints(inhibitPolicyMapping: 0)]);
		using Authority belowInhibited = inhibited.CreateIntermediate("CN=Below", more: [CertificatePolicies(P1), PolicyMappings((P1, P2))]);
		Certificate mappedLeaf = belowInhibited.IssueLeaf(more: [CertificatePolicies(P2)]);
		Certificate unmappedLeaf = belowInhibited.IssueLeaf(more: [CertificatePolicies(P1)]);
		using Authority oneMore = root.CreateIntermediate("CN=One more", more: [CertificatePolicies(P1), PolicyConstraints(inhibitPolicyMapping: 1)]);
		using Authority belowOneMore = oneMore.CreateIntermediate("CN=Below one more", more: [CertificatePolicies(P1), PolicyMappings((P1, P2))]);
		Certificate allowedLeaf = belowOneMore.IssueLeaf(more: [CertificatePolicies(P2)]);
		using Authority direct = root.CreateIntermediate("CN=Direct", more: [CertificatePolicies(P1), PolicyMappings((P1, P2))]);
		Certificate directLeaf = direct.IssueLeaf(more: [CertificatePolicies(P2)]);

		using (Assert.Multiple())
		{
			await AssertRejected(await ValidateWith(root, [mappedLeaf, belowInhibited.Certificate, inhibited.Certificate], explicitPolicy: true), mappedLeaf, belowInhibited.Certificate, inhibited.Certificate, root.Certificate);
			await AssertRejected(await ValidateWith(root, [unmappedLeaf, belowInhibited.Certificate, inhibited.Certificate], explicitPolicy: true), unmappedLeaf, belowInhibited.Certificate, inhibited.Certificate, root.Certificate);
			await AssertValid(await ValidateWith(root, [allowedLeaf, belowOneMore.Certificate, oneMore.Certificate], explicitPolicy: true), allowedLeaf, belowOneMore.Certificate, oneMore.Certificate, root.Certificate);
			await AssertValid(await ValidateWith(root, [directLeaf, direct.Certificate], explicitPolicy: true), directLeaf, direct.Certificate, root.Certificate);
			await AssertRejected(await ValidateWith(root, [directLeaf, direct.Certificate], explicitPolicy: true, inhibitMapping: true), directLeaf, direct.Certificate, root.Certificate);
		}
	}

	// RFC 5280, Secs. 6.1.1 (g) and 6.1.3 (d)(2): once inhibit_anyPolicy reaches zero, anyPolicy no longer matches, except in a self-issued certificate that is not the last.
	[Test]
	public async Task InhibitsAnyPolicy()
	{
		using Authority root = Authority.CreateRoot();
		using Authority none = root.CreateIntermediate(more: [CertificatePolicies(P1), InhibitAnyPolicy(0)]);
		Certificate anyLeaf = none.IssueLeaf(more: [CertificatePolicies(AnyPolicyOid)]);
		Certificate policyLeaf = none.IssueLeaf(more: [CertificatePolicies(P1)]);
		Certificate bothLeaf = none.IssueLeaf(more: [CertificatePolicies(P1, AnyPolicyOid)]);
		using Authority one = root.CreateIntermediate("CN=One", more: [CertificatePolicies(P1), InhibitAnyPolicy(1)]);
		using Authority any = one.CreateIntermediate("CN=Any", more: [CertificatePolicies(AnyPolicyOid)]);
		Certificate belowAnyPolicy = any.IssueLeaf(more: [CertificatePolicies(P1)]);
		Certificate belowAnyAny = any.IssueLeaf(more: [CertificatePolicies(AnyPolicyOid)]);
		using Authority selfIssued = one.CreateIntermediate(subject: one.Name, more: [CertificatePolicies(AnyPolicyOid)]);
		Certificate belowSelfIssued = selfIssued.IssueLeaf(more: [CertificatePolicies(P1)]);

		using (Assert.Multiple())
		{
			await AssertRejected(await ValidateWith(root, [anyLeaf, none.Certificate], explicitPolicy: true), anyLeaf, none.Certificate, root.Certificate);
			await AssertValid(await ValidateWith(root, [policyLeaf, none.Certificate], explicitPolicy: true), policyLeaf, none.Certificate, root.Certificate);
			await AssertValid(await ValidateWith(root, [bothLeaf, none.Certificate], explicitPolicy: true), bothLeaf, none.Certificate, root.Certificate);
			await AssertValid(await ValidateWith(root, [belowAnyPolicy, any.Certificate, one.Certificate], explicitPolicy: true), belowAnyPolicy, any.Certificate, one.Certificate, root.Certificate);
			await AssertRejected(await ValidateWith(root, [belowAnyAny, any.Certificate, one.Certificate], explicitPolicy: true), belowAnyAny, any.Certificate, one.Certificate, root.Certificate);
			await AssertRejected(await ValidateWith(root, [belowAnyPolicy, any.Certificate, one.Certificate], explicitPolicy: true, inhibitAny: true), belowAnyPolicy, any.Certificate, one.Certificate, root.Certificate);
			await AssertValid(await ValidateWith(root, [belowSelfIssued, selfIssued.Certificate, one.Certificate], explicitPolicy: true), belowSelfIssued, selfIssued.Certificate, one.Certificate, root.Certificate);
		}
	}

	// RFC 5280, Secs. 6.1.4 (h) and (i) and 6.1.5 (a) and (b): requireExplicitPolicy counts the certificates that are not self-issued, and takes effect only where it reaches zero.
	[Test]
	public async Task CountsRequireExplicitPolicy()
	{
		using Authority root = Authority.CreateRoot();
		using Authority requiresNow = root.CreateIntermediate(more: [CertificatePolicies(P1), PolicyConstraints(requireExplicitPolicy: 0)]);
		Certificate leafWithoutPolicies = requiresNow.IssueLeaf();
		Certificate leafWithPolicy = requiresNow.IssueLeaf(more: [CertificatePolicies(P1)]);
		using Authority requiresLater = root.CreateIntermediate("CN=Later", more: [CertificatePolicies(P1), PolicyConstraints(requireExplicitPolicy: 1)]);
		using Authority noPolicy = requiresLater.CreateIntermediate("CN=No policy");
		Certificate belowNoPolicy = noPolicy.IssueLeaf(more: [CertificatePolicies(P1)]);
		using Authority requiresTwo = root.CreateIntermediate("CN=Two", more: [CertificatePolicies(P1), PolicyConstraints(requireExplicitPolicy: 2)]);
		using Authority twoSelfIssued = requiresTwo.CreateIntermediate(subject: requiresTwo.Name);
		Certificate twoLeaf = twoSelfIssued.IssueLeaf();
		using Authority twoReencoded = requiresTwo.CreateIntermediate(subject: CommonName(Utf8StringTag, "two"));
		Certificate twoReencodedLeaf = twoReencoded.IssueLeaf();
		using Authority twoIntermediate = requiresTwo.CreateIntermediate("CN=Two more");
		Certificate twoFar = twoIntermediate.IssueLeaf();

		using (Assert.Multiple())
		{
			await AssertRejected(await ValidateWith(root, [leafWithoutPolicies, requiresNow.Certificate]), leafWithoutPolicies, requiresNow.Certificate, root.Certificate);
			await AssertValid(await ValidateWith(root, [leafWithPolicy, requiresNow.Certificate]), leafWithPolicy, requiresNow.Certificate, root.Certificate);
			await AssertValid(await ValidateWith(root, [leafWithPolicy, requiresNow.Certificate], [P1]), leafWithPolicy, requiresNow.Certificate, root.Certificate);
			await AssertRejected(await ValidateWith(root, [leafWithPolicy, requiresNow.Certificate], [P2]), leafWithPolicy, requiresNow.Certificate, root.Certificate);
			await AssertRejected(await ValidateWith(root, [belowNoPolicy, noPolicy.Certificate, requiresLater.Certificate]), belowNoPolicy, noPolicy.Certificate, requiresLater.Certificate, root.Certificate);
			await AssertValid(await ValidateWith(root, [twoLeaf, twoSelfIssued.Certificate, requiresTwo.Certificate]), twoLeaf, twoSelfIssued.Certificate, requiresTwo.Certificate, root.Certificate);
			await AssertValid(await ValidateWith(root, [twoReencodedLeaf, twoReencoded.Certificate, requiresTwo.Certificate]), twoReencodedLeaf, twoReencoded.Certificate, requiresTwo.Certificate, root.Certificate);
			await AssertRejected(await ValidateWith(root, [twoFar, twoIntermediate.Certificate, requiresTwo.Certificate]), twoFar, twoIntermediate.Certificate, requiresTwo.Certificate, root.Certificate);
		}
	}

	// RFC 5280, Sec. 6.1.5 (b): the peer's certificate can require an explicit policy for itself, but its value of more than zero does nothing, and neither do its other policy extensions.
	[Test]
	public async Task ThePeersCertificateRequiresAPolicyOnlyAtZero()
	{
		using Authority root = Authority.CreateRoot();
		using Authority issuing = root.CreateIntermediate(more: [CertificatePolicies(P1)]);
		Certificate atZero = issuing.IssueLeaf(more: [CertificatePolicies(P2), PolicyConstraints(requireExplicitPolicy: 0)]);
		Certificate atOne = issuing.IssueLeaf(more: [CertificatePolicies(P2), PolicyConstraints(requireExplicitPolicy: 1)]);
		Certificate inhibitingLeaf = issuing.IssueLeaf(more: [CertificatePolicies(P2), InhibitAnyPolicy(0), PolicyConstraints(inhibitPolicyMapping: 0)]);

		using (Assert.Multiple())
		{
			await AssertRejected(await ValidateWith(root, [atZero, issuing.Certificate]), atZero, issuing.Certificate, root.Certificate);
			await AssertValid(await ValidateWith(root, [atOne, issuing.Certificate]), atOne, issuing.Certificate, root.Certificate);
			await AssertValid(await ValidateWith(root, [inhibitingLeaf, issuing.Certificate]), inhibitingLeaf, issuing.Certificate, root.Certificate);
		}
	}

	// RFC 5280, Sec. 6.1.1: a trust anchor takes no part in policy processing, whatever its extensions say, whether it issues the peer's certificate or is that certificate.
	[Test]
	public async Task ATrustAnchorTakesNoPartInPolicyProcessing()
	{
		using Authority root = Authority.CreateRoot(more: [CertificatePolicies(P2), PolicyConstraints(requireExplicitPolicy: 0), InhibitAnyPolicy(0, critical: false)]);
		Certificate leaf = root.IssueLeaf();
		Certificate anyLeaf = root.IssueLeaf(more: [CertificatePolicies(AnyPolicyOid)]);

		using (Assert.Multiple())
		{
			await AssertValid(await ValidateWith(root, [leaf]), leaf, root.Certificate);
			await AssertValid(await ValidateWith(root, [anyLeaf], [P1], explicitPolicy: true), anyLeaf, root.Certificate);
			await AssertValid(await ValidateWith(root, [root.Certificate], explicitPolicy: true), root.Certificate);
		}
	}

	// RFC 5280, Sec. 6.1: the check runs when a path reaches a trust anchor, so a path that fails it gives way to the next candidate, and if none is valid the best is reported, with the policy error.
	[Test]
	public async Task TriesTheNextCandidateWhenAPathFailsThePolicyCheck()
	{
		using Authority root = Authority.CreateRoot();
		using EcdsaP256 intermediateKey = EcdsaP256.GenerateKey();
		byte[] subject = X509TestUtils.Name("CN=Cross");
		byte[] spki = ExportSubjectPublicKeyInfo(intermediateKey);
		Certificate failing = root.Issue(new Template { Subject = subject, SubjectPublicKeyInfo = spki, Extensions = [.. CaExtensions(spki), AuthorityKeyIdentifier(root.KeyIdentifier), CertificatePolicies(P2)] });
		Certificate passing = root.Issue(new Template { Subject = subject, SubjectPublicKeyInfo = spki, Extensions = [.. CaExtensions(spki), AuthorityKeyIdentifier(root.KeyIdentifier), CertificatePolicies(P1)] });
		Template leafTemplate = new()
		{
			Subject = X509TestUtils.Name("CN=Leaf"),
			SubjectPublicKeyInfo = ExportSubjectPublicKeyInfo(intermediateKey),
			Extensions = [SubjectAlternativeNames("example.com"), CertificatePolicies(P1), PolicyConstraints(requireExplicitPolicy: 0)]
		};
		Certificate leaf = Sign(leafTemplate, subject, intermediateKey, SignatureAlgorithm.EcdsaSha256);

		using (Assert.Multiple())
		{
			await AssertValid(await ValidateWith(root, [leaf, failing, passing]), leaf, passing, root.Certificate);
			await AssertValid(await ValidateWith(root, [leaf, passing, failing]), leaf, passing, root.Certificate);
			await AssertRejected(await ValidateWith(root, [leaf, failing]), leaf, failing, root.Certificate);
		}
	}

	// RFC 5280, Secs. 4.2.1.4, 4.2.1.5, 4.2.1.11 and 4.2.1.14: the syntax of the extensions.
	public static IEnumerable<Func<(string Case, CertificateExtension Extension)>> MalformedExtensions()
	{
		yield return () => ("a duplicate policy", CertificatePolicies(P1, P1));
		yield return () => ("anyPolicy twice", CertificatePolicies(AnyPolicyOid, AnyPolicyOid));
		yield return () => ("no policy", new CertificateExtension(CertificatePoliciesOid, false, Sequence()));
		yield return () => ("a policy that is not an OBJECT IDENTIFIER", new CertificateExtension(CertificatePoliciesOid, false, Sequence(Sequence(Tlv(0x02, [0x01])))));
		yield return () => ("an OBJECT IDENTIFIER with a leading 0x80", new CertificateExtension(CertificatePoliciesOid, false, Sequence(Sequence(Tlv(0x06, [0x55, 0x80, 0x1D])))));
		yield return () => ("an OBJECT IDENTIFIER that ends mid-arc", new CertificateExtension(CertificatePoliciesOid, false, Sequence(Sequence(Tlv(0x06, [0x55, 0x81])))));
		yield return () => ("qualifiers that are not a SEQUENCE", new CertificateExtension(CertificatePoliciesOid, false, Sequence(Sequence(Oid(P1), [0x05, 0x00]))));
		yield return () => ("empty qualifiers", new CertificateExtension(CertificatePoliciesOid, false, Sequence(Sequence(Oid(P1), Sequence()))));
		yield return () => ("a qualifier without an identifier, in an extension that is not critical", new CertificateExtension(CertificatePoliciesOid, false, Sequence(Sequence(Oid(P1), Sequence(Sequence([0x05, 0x00]))))));
		yield return () => ("a qualifier without a value, in an extension that is not critical", new CertificateExtension(CertificatePoliciesOid, false, Sequence(Sequence(Oid(P1), Sequence(Sequence(Oid("1.3.6.1.5.5.7.2.2")))))));
		yield return () => ("a qualifier with a second value, in an extension that is not critical", new CertificateExtension(CertificatePoliciesOid, false, Sequence(Sequence(Oid(P1), Sequence(Sequence(Oid("1.3.6.1.5.5.7.2.1"), Tlv(0x16), Tlv(0x16)))))));
		yield return () => ("another field after the qualifiers", new CertificateExtension(CertificatePoliciesOid, false, Sequence(Sequence(Oid(P1), Sequence(Sequence(Oid("1.3.6.1.5.5.7.2.1"), Tlv(0x16))), [0x05, 0x00]))));
		yield return () => ("no mapping", new CertificateExtension(PolicyMappingsOid, false, Sequence()));
		yield return () => ("a mapping from anyPolicy", PolicyMappings((AnyPolicyOid, P1)));
		yield return () => ("a mapping to anyPolicy", PolicyMappings((P1, AnyPolicyOid)));
		yield return () => ("a mapping with one policy", new CertificateExtension(PolicyMappingsOid, false, Sequence(Sequence(Oid(P1)))));
		yield return () => ("empty policy constraints", new CertificateExtension(PolicyConstraintsOid, true, Sequence()));
		yield return () => ("a negative requireExplicitPolicy", new CertificateExtension(PolicyConstraintsOid, true, Sequence(Tlv(0x80, [0xFF]))));
		yield return () => ("policy constraints in the wrong order", new CertificateExtension(PolicyConstraintsOid, true, Sequence(Tlv(0x81, [0x00]), Tlv(0x80, [0x00]))));
		yield return () => ("a requireExplicitPolicy of a universal tag", new CertificateExtension(PolicyConstraintsOid, true, Sequence([0x02, 0x01, 0x00])));
		yield return () => ("a negative inhibitAnyPolicy", new CertificateExtension(InhibitAnyPolicyOid, true, [0x02, 0x01, 0xFF]));
		yield return () => ("an inhibitAnyPolicy that is not an INTEGER", new CertificateExtension(InhibitAnyPolicyOid, true, [0x05, 0x00]));
		yield return () => ("a value after the integer", new CertificateExtension(InhibitAnyPolicyOid, true, [0x02, 0x01, 0x00, 0x05, 0x00]));
	}

	[Test]
	[MethodDataSource(nameof(MalformedExtensions))]
	public async Task RefusesAPolicyExtensionThatIsMalformed(string @case, CertificateExtension extension)
	{
		using Authority root = Authority.CreateRoot();
		using Authority issuing = root.CreateIntermediate(more: [extension]);
		Certificate leaf = issuing.IssueLeaf();

		await AssertInvalid(await Validate([root.Certificate], [leaf, issuing.Certificate]), [CertificateValidationError.Malformed], CertificatePathEnd.TrustAnchor, @case, [leaf, issuing.Certificate, root.Certificate]);
	}

	// The qualifiers that RFC 5280 defines may be in a critical extension, and a value of SkipCerts too large for an int is as good as the largest.
	[Test]
	public async Task AcceptsQualifiersAndLargeSkipCerts()
	{
		using Authority root = Authority.CreateRoot();
		CertificateExtension withQualifier = new(CertificatePoliciesOid, true, Sequence(Sequence(Oid(P1), Sequence(Sequence(Oid("1.3.6.1.5.5.7.2.1"), Tlv(0x16)), Sequence(Oid("1.3.6.1.5.5.7.2.2"), Sequence())))));
		CertificateExtension large = new(PolicyConstraintsOid, true, Sequence(Tlv(0x80, [0x7F, 0xFF, 0xFF, 0xFF, 0xFF]), Tlv(0x81, [0x00, 0xFF, 0xFF, 0xFF, 0xFF])));
		CertificateExtension largeAny = new(InhibitAnyPolicyOid, true, [0x02, 0x08, 0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]);
		using Authority issuing = root.CreateIntermediate(more: [withQualifier, large, largeAny, PolicyMappings((P3, P2))]);
		Certificate leaf = issuing.IssueLeaf(more: [withQualifier]);

		await AssertValid(await ValidateWith(root, [leaf, issuing.Certificate], explicitPolicy: true), leaf, issuing.Certificate, root.Certificate);
	}

	// A PolicyQualifierInfo of id-qt-unotice whose UserNotice has these fields.
	private static byte[] UserNotice(params byte[][] fields)
	{
		return Sequence(Oid("1.3.6.1.5.5.7.2.2"), Sequence(fields));
	}

	private static byte[] NoticeReference(byte[] organization, params byte[][] numbers)
	{
		return Sequence(organization, Sequence(numbers));
	}

	private static byte[] Utf8Text(string text)
	{
		return Tlv(0x0C, Encoding.UTF8.GetBytes(text));
	}

	public static IEnumerable<Func<(string Case, byte[] Qualifier)>> InterpretedQualifiers()
	{
		yield return () => ("a CPS pointer", Sequence(Oid("1.3.6.1.5.5.7.2.1"), Tlv(0x16, "http://cps.test/"u8.ToArray())));
		yield return () => ("an empty CPS pointer", Sequence(Oid("1.3.6.1.5.5.7.2.1"), Tlv(0x16)));
		yield return () => ("an empty user notice", UserNotice());
		yield return () => ("an explicit text that is an IA5String", UserNotice(Tlv(0x16, "Notice"u8.ToArray())));
		yield return () => ("an explicit text that is a VisibleString", UserNotice(Tlv(0x1A, "Notice"u8.ToArray())));
		yield return () => ("an explicit text that is a BMPString", UserNotice(Tlv(0x1E, Encoding.BigEndianUnicode.GetBytes("通知"))));
		yield return () => ("an explicit text that is a UTF8String", UserNotice(Utf8Text("通知")));
		yield return () => ("an explicit text longer than 200 characters", UserNotice(Utf8Text(new string('n', 300))));
		yield return () => ("a notice reference", UserNotice(NoticeReference(Utf8Text("Org"), [0x02, 0x01, 0x01], [0x02, 0x02, 0x00, 0x80])));
		yield return () => ("a notice reference and an explicit text", UserNotice(NoticeReference(Tlv(0x1A, "Org"u8.ToArray()), [0x02, 0x01, 0x01]), Utf8Text("Notice")));
	}

	// RFC 5280, Sec. 4.2.1.4: the qualifiers that it defines may be in a critical extension, with an explicitText longer than its 200 characters, which the section asks users to accept.
	[Test]
	[MethodDataSource(nameof(InterpretedQualifiers))]
	public async Task AcceptsAnInterpretedQualifierInACriticalExtension(string @case, byte[] qualifier)
	{
		using Authority root = Authority.CreateRoot();
		using Authority issuing = root.CreateIntermediate(more: [new CertificateExtension(CertificatePoliciesOid, true, Sequence(Sequence(Oid(P1), Sequence(qualifier))))]);
		Certificate leaf = issuing.IssueLeaf();

		await AssertValid(await Validate([root.Certificate], [leaf, issuing.Certificate]), leaf, issuing.Certificate, root.Certificate);
	}

	public static IEnumerable<Func<(string Case, byte[] Qualifier)>> UninterpretedQualifiers()
	{
		yield return () => ("an unrecognized qualifier", Sequence(Oid("1.3.6.1.4.1.55738.77.9"), [0x05, 0x00]));
		yield return () => ("a CPS pointer that is NULL", Sequence(Oid("1.3.6.1.5.5.7.2.1"), [0x05, 0x00]));
		yield return () => ("a CPS pointer that is a UTF8String", Sequence(Oid("1.3.6.1.5.5.7.2.1"), Tlv(0x0C)));
		yield return () => ("a CPS pointer that is a constructed IA5String", Sequence(Oid("1.3.6.1.5.5.7.2.1"), Tlv(0x36)));
		yield return () => ("a CPS pointer with a byte above 0x7F", Sequence(Oid("1.3.6.1.5.5.7.2.1"), Tlv(0x16, [0x80])));
		yield return () => ("a user notice that is NULL", Sequence(Oid("1.3.6.1.5.5.7.2.2"), [0x05, 0x00]));
		yield return () => ("a user notice that is an IA5String", Sequence(Oid("1.3.6.1.5.5.7.2.2"), Tlv(0x16)));
		yield return () => ("a user notice with a truncated explicit text", UserNotice([0x0C, 0x05, 0x4E]));
		yield return () => ("a user notice with NULL for its notice reference", UserNotice([0x05, 0x00]));
		yield return () => ("a user notice with two explicit texts", UserNotice(Utf8Text("A"), Utf8Text("B")));
		yield return () => ("a user notice with its explicit text first", UserNotice(Utf8Text("Notice"), NoticeReference(Utf8Text("Org"), [0x02, 0x01, 0x01])));
		yield return () => ("an explicit text that is an OCTET STRING", UserNotice(Tlv(0x04, "Notice"u8.ToArray())));
		yield return () => ("an explicit text that is a constructed UTF8String", UserNotice(Tlv(0x2C, Utf8Text("Notice"))));
		yield return () => ("an explicit text that is not UTF-8", UserNotice(Tlv(0x0C, [0xFF])));
		yield return () => ("an explicit text that is a BMPString of odd length", UserNotice(Tlv(0x1E, [0x00])));
		yield return () => ("an explicit text that is a VisibleString with a control character", UserNotice(Tlv(0x1A, [0x0A])));
		yield return () => ("an empty notice reference", UserNotice(Sequence()));
		yield return () => ("a notice reference without notice numbers", UserNotice(Sequence(Utf8Text("Org"))));
		yield return () => ("a notice reference whose organization is an OCTET STRING", UserNotice(NoticeReference(Tlv(0x04, "Org"u8.ToArray()), [0x02, 0x01, 0x01])));
		yield return () => ("a notice number that is not minimal", UserNotice(NoticeReference(Utf8Text("Org"), [0x02, 0x02, 0x00, 0x01])));
		yield return () => ("a notice number that is NULL", UserNotice(NoticeReference(Utf8Text("Org"), [0x05, 0x00])));
	}

	// RFC 5280, Sec. 4.2.1.4: a validator must interpret the qualifiers of a critical extension or reject the certificate; those of an extension that is not critical do not matter.
	[Test]
	[MethodDataSource(nameof(UninterpretedQualifiers))]
	public async Task RefusesAnUninterpretedQualifierOnlyInACriticalExtension(string @case, byte[] qualifier)
	{
		using Authority root = Authority.CreateRoot();
		byte[] policies = Sequence(Sequence(Oid(P1), Sequence(qualifier)));
		using Authority critical = root.CreateIntermediate(more: [new CertificateExtension(CertificatePoliciesOid, true, policies)]);
		using Authority noncritical = root.CreateIntermediate("CN=Noncritical", more: [new CertificateExtension(CertificatePoliciesOid, false, policies)]);
		Certificate leafOfCritical = critical.IssueLeaf();
		Certificate leafOfNoncritical = noncritical.IssueLeaf();

		using (Assert.Multiple())
		{
			await AssertInvalid(await Validate([root.Certificate], [leafOfCritical, critical.Certificate]), [CertificateValidationError.NotValidForUsage], CertificatePathEnd.TrustAnchor, leafOfCritical, critical.Certificate, root.Certificate);
			await AssertValid(await Validate([root.Certificate], [leafOfNoncritical, noncritical.Certificate]), leafOfNoncritical, noncritical.Certificate, root.Certificate);
		}
	}

	// An initial policy that no certificate can hold, longer than AsnDecoder reads, is still an object identifier: it matches nothing.
	[Test]
	public async Task AcceptsAnInitialPolicyBeyondTheLimitsOfACertificate()
	{
		using Authority root = Authority.CreateRoot();
		string longPolicy = string.Join('.', Enumerable.Repeat("1", 70));
		Certificate leaf = root.IssueLeaf(more: [CertificatePolicies(P1)]);

		await AssertRejected(await ValidateWith(root, [leaf], [longPolicy], explicitPolicy: true), leaf, root.Certificate);
	}

	// RFC 5280, Secs. 4.2.1.11 and 4.2.1.14: a certificate that takes part in policy processing must mark these extensions critical.
	[Test]
	public async Task RefusesNonCriticalPolicyConstraintsAndInhibitAnyPolicy()
	{
		using Authority root = Authority.CreateRoot();
		using Authority noncriticalConstraints = root.CreateIntermediate(more: [PolicyConstraints(requireExplicitPolicy: 3, critical: false)]);
		using Authority noncriticalInhibit = root.CreateIntermediate("CN=Inhibit", more: [InhibitAnyPolicy(3, critical: false)]);
		Certificate leafOfConstraints = noncriticalConstraints.IssueLeaf();
		Certificate leafOfInhibit = noncriticalInhibit.IssueLeaf();
		Certificate noncriticalLeaf = root.IssueLeaf(more: [PolicyConstraints(requireExplicitPolicy: 1, critical: false)]);

		using (Assert.Multiple())
		{
			await AssertInvalid(await Validate([root.Certificate], [leafOfConstraints, noncriticalConstraints.Certificate]), [CertificateValidationError.Malformed], CertificatePathEnd.TrustAnchor, leafOfConstraints, noncriticalConstraints.Certificate, root.Certificate);
			await AssertInvalid(await Validate([root.Certificate], [leafOfInhibit, noncriticalInhibit.Certificate]), [CertificateValidationError.Malformed], CertificatePathEnd.TrustAnchor, leafOfInhibit, noncriticalInhibit.Certificate, root.Certificate);
			await AssertInvalid(await Validate([root.Certificate], [noncriticalLeaf]), [CertificateValidationError.Malformed], CertificatePathEnd.TrustAnchor, noncriticalLeaf, root.Certificate);
		}
	}

	// The graph is linear in the policies and mappings of the path, and has a limit: a path of many policies that anyPolicy passes down would exceed it, and the validation ends at once with Unspecified.
	[Test]
	public async Task StopsBeforeThePolicyGraphGrowsTooLarge()
	{
		string[] policies = [.. Enumerable.Range(0, 1 << 13).Select(static i => $"1.3.6.1.4.1.55738.88.{i}")];
		using Authority root = Authority.CreateRoot();
		Authority[] intermediates = new Authority[8];
		intermediates[0] = root.CreateIntermediate("CN=Top", more: [CertificatePolicies(policies)]);

		for (int i = 1; i < intermediates.Length; ++i)
		{
			intermediates[i] = intermediates[i - 1].CreateIntermediate($"CN=Below {i}", more: [CertificatePolicies(AnyPolicyOid)]);
		}

		Certificate leaf = intermediates[^1].IssueLeaf(more: [CertificatePolicies(AnyPolicyOid)]);
		Certificate[] presented = [leaf, .. intermediates.Reverse().Select(static authority => authority.Certificate)];
		Stopwatch stopwatch = Stopwatch.StartNew();

		try
		{
			CertificateValidationResult result = await ValidateWith(root, presented, explicitPolicy: true);
			stopwatch.Stop();

			using (Assert.Multiple())
			{
				await Assert.That(result.Errors).Contains(CertificateValidationError.Unspecified);
				await Assert.That(stopwatch.Elapsed).IsLessThan(TimeSpan.FromSeconds(30));
			}
		}
		finally
		{
			foreach (Authority intermediate in intermediates)
			{
				intermediate.Dispose();
			}
		}
	}

	// The mapping of every policy to every other on each of several certificates multiplies a tree of RFC 5280, but only adds to the graph of RFC 9618.
	[Test]
	public async Task ACrossProductOfMappingsDoesNotMultiplyTheWork()
	{
		string[] policies = [.. Enumerable.Range(0, 24).Select(static i => $"1.3.6.1.4.1.55738.89.{i}")];
		(string Issuer, string Subject)[] crossProduct = [.. from issuer in policies from subject in policies select (issuer, subject)];
		using Authority root = Authority.CreateRoot();
		Authority[] intermediates = new Authority[8];
		Authority parent = root;

		for (int i = 0; i < intermediates.Length; ++i)
		{
			intermediates[i] = parent.CreateIntermediate($"CN=Level {i}", more: [CertificatePolicies(policies), PolicyMappings(crossProduct)]);
			parent = intermediates[i];
		}

		Certificate leaf = intermediates[^1].IssueLeaf(more: [CertificatePolicies(policies)]);
		Certificate[] presented = [leaf, .. intermediates.Reverse().Select(static authority => authority.Certificate)];
		Stopwatch stopwatch = Stopwatch.StartNew();

		try
		{
			CertificateValidationResult result = await ValidateWith(root, presented, explicitPolicy: true);
			stopwatch.Stop();

			using (Assert.Multiple())
			{
				await Assert.That(result.IsValid).IsTrue().Because($"[{string.Join(", ", result.Errors)}] {result.Message}");
				await Assert.That(stopwatch.Elapsed).IsLessThan(TimeSpan.FromSeconds(30));
			}
		}
		finally
		{
			foreach (Authority intermediate in intermediates)
			{
				intermediate.Dispose();
			}
		}
	}

	[Test]
	public async Task ChecksTheInitialPoliciesItIsGiven()
	{
		using Authority root = Authority.CreateRoot();
		using TrustAnchorCertificateValidator defaults = new([root.Certificate], SignatureKey.ImportSubjectPublicKeyInfo);
		using TrustAnchorCertificateValidator given = new([root.Certificate], SignatureKey.ImportSubjectPublicKeyInfo) { InitialPolicies = [P1, P2] };
		string[] mutable = [P1];
		using TrustAnchorCertificateValidator copying = new([root.Certificate], SignatureKey.ImportSubjectPublicKeyInfo) { InitialPolicies = mutable };
		mutable[0] = P2;

		using (Assert.Multiple())
		{
			await Assert.That(defaults.InitialPolicies).IsEquivalentTo([AnyPolicyOid]);
			await Assert.That(defaults.RequireExplicitPolicy).IsFalse();
			await Assert.That(defaults.InhibitPolicyMapping).IsFalse();
			await Assert.That(defaults.InhibitAnyPolicy).IsFalse();
			await Assert.That(given.InitialPolicies).IsEquivalentTo([P1, P2]);
			await Assert.That(copying.InitialPolicies).IsEquivalentTo([P1]);
			await Assert.That(() => new TrustAnchorCertificateValidator([root.Certificate], SignatureKey.ImportSubjectPublicKeyInfo) { InitialPolicies = null! }).Throws<ArgumentNullException>();
			await Assert.That(() => new TrustAnchorCertificateValidator([root.Certificate], SignatureKey.ImportSubjectPublicKeyInfo) { InitialPolicies = [] }).Throws<ArgumentException>();
			await Assert.That(() => new TrustAnchorCertificateValidator([root.Certificate], SignatureKey.ImportSubjectPublicKeyInfo) { InitialPolicies = [null!] }).Throws<ArgumentException>();
			await Assert.That(() => new TrustAnchorCertificateValidator([root.Certificate], SignatureKey.ImportSubjectPublicKeyInfo) { InitialPolicies = ["not an oid"] }).Throws<ArgumentException>();
		}
	}
}
