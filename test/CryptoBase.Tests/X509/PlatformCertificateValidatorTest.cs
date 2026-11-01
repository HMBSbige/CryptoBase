using CryptoBase.Abstractions.Signatures;
using CryptoBase.Signatures.Ecdsa;
using CryptoBase.X509;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using static CryptoBase.Tests.X509.X509TestUtils;

namespace CryptoBase.Tests.X509;

[SuppressMessage("ReSharper", "AccessToDisposedClosure")]
public class PlatformCertificateValidatorTest
{
	private const X509VerificationFlags IgnoreEnd = X509VerificationFlags.IgnoreEndRevocationUnknown;
	private const X509VerificationFlags IgnoreAuthority = X509VerificationFlags.IgnoreCertificateAuthorityRevocationUnknown;
	private const X509VerificationFlags IgnoreRoot = X509VerificationFlags.IgnoreRootRevocationUnknown;

	[Test]
	public async Task AcceptsAChainToATrustedRoot()
	{
		using TestPki pki = new();
		using X509Certificate2 leaf = pki.IssueLeaf(static request => request.CertificateExtensions.Add(SubjectAlternativeName("example.com", "*.example.org", "192.0.2.1")));
		PlatformCertificateValidator validator = pki.Validator();

		using (Assert.Multiple())
		{
			foreach (string? hostName in (string?[])["example.com", "EXAMPLE.com.", "a.example.org", "192.0.2.1", null])
			{
				CertificateValidationResult result = await validator.ValidateAsync(pki.Context(leaf, CertificateUsage.ServerAuthentication, hostName));

				await Assert.That(result.IsValid).IsTrue().Because($"{hostName}: {result.Error} {result.Message}");
				await Assert.That(result.Error).IsEqualTo(CertificateValidationError.Unspecified);
			}
		}
	}

	[Test]
	public async Task HostNamesMatchOnlyTheSubjectAlternativeName()
	{
		using TestPki pki = new();
		using X509Certificate2 withAlternativeName = pki.IssueLeaf(static request => request.CertificateExtensions.Add(SubjectAlternativeName("example.com", "*.example.org", "xn--bcher-kva.example")), "CN=common.example");
		using X509Certificate2 commonNameOnly = pki.IssueLeaf(subject: "CN=common.example");
		PlatformCertificateValidator validator = pki.Validator();

		using (Assert.Multiple())
		{
			await Assert.That((await validator.ValidateAsync(pki.Context(withAlternativeName, CertificateUsage.ServerAuthentication, "bücher.example"))).IsValid).IsTrue();

			foreach ((X509Certificate2 leaf, string hostName) in ((X509Certificate2, string)[])[(withAlternativeName, "other.com"), (withAlternativeName, "b.a.example.org"), (withAlternativeName, "example.org"), (withAlternativeName, "common.example"), (commonNameOnly, "common.example"), (withAlternativeName, "not a host")])
			{
				CertificateValidationResult result = await validator.ValidateAsync(pki.Context(leaf, CertificateUsage.ServerAuthentication, hostName));

				await Assert.That(result.IsValid).IsFalse().Because(hostName);
				await Assert.That(result.Error).IsEqualTo(CertificateValidationError.NameMismatch).Because(hostName);
			}
		}
	}

	[Test]
	public async Task ReportsWhyAChainFails()
	{
		using TestPki pki = new();
		using X509Certificate2 leaf = pki.IssueLeaf();
		using X509Certificate2 expired = pki.IssueLeaf(notAfter: Now.AddDays(-1));
		using X509Certificate2 clientOnly = pki.IssueLeaf(eku: ClientAuthenticationOid);
		PlatformCertificateValidator validator = pki.Validator();
		Certificate[] withoutIntermediate = [Certificate.Decode(leaf.RawData)];

		using (Assert.Multiple())
		{
			await AssertError(await validator.ValidateAsync(pki.Context(expired, CertificateUsage.ServerAuthentication)), CertificateValidationError.Expired);
			await AssertError(await validator.ValidateAsync(pki.Context(clientOnly, CertificateUsage.ServerAuthentication)), CertificateValidationError.NotValidForUsage);
			await AssertError(await validator.ValidateAsync(new CertificateValidationContext(withoutIntermediate, CertificateUsage.ServerAuthentication)), CertificateValidationError.UntrustedRoot);
			await AssertError(await new PlatformCertificateValidator().ValidateAsync(pki.Context(leaf, CertificateUsage.ServerAuthentication)), CertificateValidationError.UntrustedRoot);
			await Assert.That((await validator.ValidateAsync(pki.Context(clientOnly, CertificateUsage.ClientAuthentication))).IsValid).IsTrue();
		}
	}

	// The validator does not check the key usage of the leaf.
	[Test]
	public async Task LeavesTheKeyUsageOfTheLeafToTheCaller()
	{
		using TestPki pki = new();
		using X509Certificate2 leaf = pki.IssueLeaf(keyUsage: X509KeyUsageFlags.KeyAgreement);
		CertificateValidationContext context = pki.Context(leaf, CertificateUsage.ServerAuthentication);

		CertificateValidationResult result = await pki.Validator().ValidateAsync(context);

		using (Assert.Multiple())
		{
			await Assert.That(result.IsValid).IsTrue().Because($"{result.Error} {result.Message}");
			await Assert.That(context.PresentedCertificates[0].KeyUsage).IsEqualTo(X509KeyUsageFlags.KeyAgreement);
		}
	}

	[Test]
	public async Task TrustsSelfSignedCryptoBaseCertificates()
	{
		using EcdsaP384 key = EcdsaP384.GenerateKey();
		Certificate certificate = SelfSigned(key, SignatureAlgorithm.EcdsaSha384, "CN=CryptoBase", new CertificateExtension("2.5.29.17", false, SubjectAlternativeName("cryptobase.example").RawData));
		using X509Certificate2 root = X509CertificateLoader.LoadCertificate(certificate.Encoded.Span);

		CertificateValidationResult result = await new PlatformCertificateValidator(TrustOnly(root)).ValidateAsync(new CertificateValidationContext([certificate], CertificateUsage.ServerAuthentication) { HostName = "cryptobase.example" });

		using (Assert.Multiple())
		{
			await Assert.That(result.IsValid).IsTrue().Because($"{result.Error} {result.Message}");
			await Assert.That(result.Path).Count().IsEqualTo(1);
			await Assert.That(result.Path[0]).IsSameReferenceAs(certificate);
			await Assert.That(result.PathEnd).IsEqualTo(CertificatePathEnd.TrustAnchor);
		}
	}

	[Test]
	public async Task CopiesThePolicyAndItsCertificates()
	{
		using TestPki pki = new();
		using X509Certificate2 leaf = pki.IssueLeaf();
		X509ChainPolicy policy = pki.Policy();
		X509Certificate2 root = X509CertificateLoader.LoadCertificate(policy.CustomTrustStore[0].RawDataMemory.Span);
		X509Certificate2 intermediate = X509CertificateLoader.LoadCertificate(pki.Intermediate.RawDataMemory.Span);
		policy.CustomTrustStore[0] = root;
		policy.ExtraStore.Add(intermediate);
		PlatformCertificateValidator validator = new(policy);
		root.Dispose();
		intermediate.Dispose();
		policy.CustomTrustStore.Clear();
		policy.ExtraStore.Clear();
		policy.TrustMode = X509ChainTrustMode.System;
		Certificate[] leafOnly = [Certificate.Decode(leaf.RawData)];

		CertificateValidationResult first = await validator.ValidateAsync(new CertificateValidationContext(leafOnly, CertificateUsage.ClientAuthentication));
		CertificateValidationResult second = await validator.ValidateAsync(new CertificateValidationContext(leafOnly, CertificateUsage.ServerAuthentication));

		using (Assert.Multiple())
		{
			await AssertError(first, CertificateValidationError.NotValidForUsage);

			// Neither the changes to the policy after construction, the disposal of its certificates nor the usage of the first validation reach the second.
			await Assert.That(second.IsValid).IsTrue().Because($"{second.Error} {second.Message}");
		}
	}

	[Test]
	[Arguments(CertificateUsage.ServerAuthentication, ServerAuthenticationOid)]
	[Arguments(CertificateUsage.ClientAuthentication, ClientAuthenticationOid)]
	public async Task AcceptsAPolicyThatAlreadyAsksForTheUsage(CertificateUsage usage, string eku)
	{
		using TestPki pki = new();
		using X509Certificate2 leaf = pki.IssueLeaf(eku: eku);
		X509ChainPolicy policy = pki.Policy();
		policy.ApplicationPolicy.Add(new Oid(eku));

		CertificateValidationResult result = await new PlatformCertificateValidator(policy).ValidateAsync(pki.Context(leaf, usage));

		await Assert.That(result.IsValid).IsTrue().Because($"{result.Error} {result.Message}");
	}

	// The flags of the policy apply to every check of the platform, the usage included, but not to the host name, which the validator checks itself.
	[Test]
	public async Task TheFlagsOfThePolicyRelaxOnlyThePlatformChecks()
	{
		using TestPki pki = new();
		using X509Certificate2 clientOnly = pki.IssueLeaf(static request => request.CertificateExtensions.Add(SubjectAlternativeName("example.com")), eku: ClientAuthenticationOid);
		X509ChainPolicy ignoreWrongUsage = pki.Policy();
		ignoreWrongUsage.VerificationFlags = X509VerificationFlags.IgnoreWrongUsage;
		X509ChainPolicy allFlags = pki.Policy();
		allFlags.VerificationFlags = X509VerificationFlags.AllFlags;

		CertificateValidationResult wrongUsage = await new PlatformCertificateValidator(ignoreWrongUsage).ValidateAsync(pki.Context(clientOnly, CertificateUsage.ServerAuthentication, "example.com"));
		CertificateValidationResult wrongName = await new PlatformCertificateValidator(allFlags).ValidateAsync(pki.Context(clientOnly, CertificateUsage.ServerAuthentication, "other.com"));

		using (Assert.Multiple())
		{
			await Assert.That(wrongUsage.IsValid).IsTrue().Because($"{wrongUsage.Error} {wrongUsage.Message}");
			await AssertError(wrongName, CertificateValidationError.NameMismatch);
		}
	}

	[Test]
	public async Task HonorsCancellation()
	{
		using TestPki pki = new();
		using X509Certificate2 leaf = pki.IssueLeaf();
		using CancellationTokenSource canceled = new();
		await canceled.CancelAsync();
		PlatformCertificateValidator validator = pki.Validator();

		using (Assert.Multiple())
		{
			await Assert.That(async () => await validator.ValidateAsync(pki.Context(leaf, CertificateUsage.ServerAuthentication), canceled.Token)).Throws<OperationCanceledException>();
			await Assert.That(async () => await validator.ValidateAsync(null!)).ThrowsExactly<ArgumentNullException>();
		}
	}

	// Cancellation is observed until the platform starts building the chain: a token canceled when the validator last reads the clock, just before the build, cancels the validation, whether it runs synchronously, on the thread pool for retrievals, or synchronously once the deadline has passed.
	[Test]
	public async Task HonorsCancellationUntilTheBuildStarts()
	{
		using TestPki pki = new();
		using X509Certificate2 leaf = pki.IssueLeaf();
		X509ChainPolicy downloads = pki.Policy();
		downloads.DisableCertificateDownloads = false;

		using (Assert.Multiple())
		{
			foreach ((string name, X509ChainPolicy policy, DateTimeOffset? deadline, int calls) in ((string, X509ChainPolicy, DateTimeOffset?, int)[])
			[
				("synchronous", pki.Policy(), null, 1),
				("on the thread pool", downloads, Now.AddMinutes(1), 2),
				("after the deadline", downloads, Now.AddSeconds(-1), 2)
			])
			{
				using CancellationTokenSource source = new();
				CancelingClock clock = new(source, calls);
				CertificateValidationContext context = new(pki.Context(leaf, CertificateUsage.ServerAuthentication).PresentedCertificates, CertificateUsage.ServerAuthentication) { Deadline = deadline, TimeProvider = clock };

				await Assert.That(async () => await new PlatformCertificateValidator(policy).ValidateAsync(context, source.Token)).Throws<OperationCanceledException>().Because(name);
				await Assert.That(clock.Calls).IsEqualTo(calls).Because(name);
			}
		}
	}

	[Test]
	public async Task ContextsAndResultsCheckTheirValues()
	{
		Certificate certificate = SelfSignedP256();

		using (Assert.Multiple())
		{
			await Assert.That(() => new CertificateValidationContext(null!, CertificateUsage.ServerAuthentication)).ThrowsExactly<ArgumentNullException>();
			await Assert.That(() => new CertificateValidationContext([], CertificateUsage.ServerAuthentication)).Throws<ArgumentException>().WithParameterName("presentedCertificates");
			await Assert.That(() => new CertificateValidationContext([certificate, null!], CertificateUsage.ServerAuthentication)).Throws<ArgumentException>().WithParameterName("presentedCertificates");
			await Assert.That(() => new CertificateValidationContext([certificate], 0)).ThrowsExactly<ArgumentOutOfRangeException>();
			await Assert.That(() => new CertificateValidationContext([certificate], CertificateUsage.ServerAuthentication) { TimeProvider = null! }).ThrowsExactly<ArgumentNullException>();
			await Assert.That(new CertificateValidationContext([certificate], CertificateUsage.ServerAuthentication).TimeProvider).IsSameReferenceAs(TimeProvider.System);
			await Assert.That(default(CertificateValidationResult).IsValid).IsFalse();
			await Assert.That(CertificateValidationResult.Valid.IsValid).IsTrue();
			await Assert.That(CertificateValidationResult.Invalid(CertificateValidationError.Revoked, "message").Error).IsEqualTo(CertificateValidationError.Revoked);
		}
	}

	[Test]
	public async Task ReportsEveryErrorOfTheChain()
	{
		using TestPki pki = new();
		using TestPki other = new();
		using X509Certificate2 leaf = pki.IssueLeaf(eku: ClientAuthenticationOid, notAfter: Now.AddDays(-1));

		CertificateValidationResult result = await new PlatformCertificateValidator(TrustOnly(other.Root)).ValidateAsync(pki.Context(leaf, CertificateUsage.ServerAuthentication, withRoot: true));

		using (Assert.Multiple())
		{
			await Assert.That(result.Errors).IsEquivalentTo([CertificateValidationError.Expired, CertificateValidationError.UntrustedRoot, CertificateValidationError.NotValidForUsage], CollectionOrdering.Matching).Because(result.Message ?? "");
			await Assert.That(result.Error).IsEqualTo(CertificateValidationError.Expired);
		}
	}

	// What each flag ignores on Windows, Linux and macOS. The chain fails for another reason too, which the flag does not ignore: it ends at a root that the validator does not trust, or, as Windows checks no name constraints under an untrusted root, the leaf is for client authentication.
	public static IEnumerable<(string Scenario, X509VerificationFlags Flag, CertificateValidationError Ignored, CertificateValidationError Remaining)> IgnoredStatuses()
	{
		yield return ("expired leaf", X509VerificationFlags.IgnoreNotTimeValid, CertificateValidationError.Expired, CertificateValidationError.UntrustedRoot);
		yield return ("expired intermediate", X509VerificationFlags.IgnoreNotTimeValid, CertificateValidationError.Expired, CertificateValidationError.UntrustedRoot);
		yield return ("leaf for client authentication", X509VerificationFlags.IgnoreWrongUsage, CertificateValidationError.NotValidForUsage, CertificateValidationError.UntrustedRoot);
		yield return ("intermediate that is not a CA", X509VerificationFlags.IgnoreInvalidBasicConstraints, CertificateValidationError.Unspecified, CertificateValidationError.UntrustedRoot);
		yield return ("name outside the permitted subtree", X509VerificationFlags.IgnoreInvalidName, CertificateValidationError.Unspecified, CertificateValidationError.NotValidForUsage);
		yield return ("name in an excluded subtree", X509VerificationFlags.IgnoreInvalidName, CertificateValidationError.Unspecified, CertificateValidationError.NotValidForUsage);
		yield return ("leaf of unknown revocation status", X509VerificationFlags.IgnoreEndRevocationUnknown, CertificateValidationError.RevocationUnknown, CertificateValidationError.UntrustedRoot);
	}

	[Test]
	[MethodDataSource(nameof(IgnoredStatuses))]
	public async Task TheFlagsLeaveOutWhatTheyIgnore(string scenario, X509VerificationFlags flag, CertificateValidationError ignored, CertificateValidationError remaining)
	{
		using TestPki pki = scenario switch
		{
			"expired intermediate" => new TestPki(intermediateNotAfter: Now.AddDays(-1)),
			"intermediate that is not a CA" => new TestPki(intermediateIsCa: false),
			"name outside the permitted subtree" => new TestPki(configureIntermediate: static request => request.CertificateExtensions.Add(NameConstraints("example.com"))),
			"name in an excluded subtree" => new TestPki(configureIntermediate: static request => request.CertificateExtensions.Add(NameConstraints("example.com", excluded: true))),
			_ => new TestPki()
		};
		using TestPki other = new();
		string eku = remaining is CertificateValidationError.NotValidForUsage ? ClientAuthenticationOid : ServerAuthenticationOid;
		using X509Certificate2 leaf = scenario switch
		{
			"expired leaf" => pki.IssueLeaf(notAfter: Now.AddDays(-1)),
			"leaf for client authentication" => pki.IssueLeaf(eku: ClientAuthenticationOid),
			"name outside the permitted subtree" => pki.IssueLeaf(static request => request.CertificateExtensions.Add(SubjectAlternativeName("other.test")), eku: eku),
			"name in an excluded subtree" => pki.IssueLeaf(static request => request.CertificateExtensions.Add(SubjectAlternativeName("a.example.com")), eku: eku),
			_ => pki.IssueLeaf()
		};
		X509ChainPolicy policy = remaining is CertificateValidationError.UntrustedRoot ? TrustOnly(other.Root) : pki.Policy();

		// The leaf names no responder, so the status is unknown without the network.
		if (scenario is "leaf of unknown revocation status")
		{
			policy.RevocationMode = X509RevocationMode.Online;
			policy.RevocationFlag = X509RevocationFlag.EndCertificateOnly;
		}

		CertificateValidationContext context = pki.Context(leaf, CertificateUsage.ServerAuthentication, withRoot: true);
		CertificateValidationResult strict = await new PlatformCertificateValidator(policy).ValidateAsync(context);
		policy.VerificationFlags = flag;
		CertificateValidationResult relaxed = await new PlatformCertificateValidator(policy).ValidateAsync(context);

		using (Assert.Multiple())
		{
			await Assert.That(strict.Errors).IsEquivalentTo([ignored, remaining]).Because(strict.Message ?? "");
			await Assert.That(relaxed.Errors).IsEquivalentTo([remaining], CollectionOrdering.Matching).Because(relaxed.Message ?? "");
			await Assert.That(relaxed.Error).IsEqualTo(remaining);
		}
	}

	[Test]
	public async Task AllowUnknownCertificateAuthorityLeavesOutAPartialChain()
	{
		using TestPki pki = new();
		using X509Certificate2 leaf = pki.IssueLeaf(eku: ClientAuthenticationOid);
		CertificateValidationContext leafOnly = new([Certificate.Decode(leaf.RawData)], CertificateUsage.ServerAuthentication);
		X509ChainPolicy policy = pki.Policy();

		CertificateValidationResult strict = await new PlatformCertificateValidator(policy).ValidateAsync(leafOnly);
		policy.VerificationFlags = X509VerificationFlags.AllowUnknownCertificateAuthority;
		CertificateValidationResult relaxed = await new PlatformCertificateValidator(policy).ValidateAsync(leafOnly);

		using (Assert.Multiple())
		{
			await Assert.That(strict.Errors).IsEquivalentTo([CertificateValidationError.UntrustedRoot, CertificateValidationError.NotValidForUsage], CollectionOrdering.Matching).Because(strict.Message ?? "");
			await Assert.That(relaxed.Errors).IsEquivalentTo([CertificateValidationError.NotValidForUsage], CollectionOrdering.Matching).Because(relaxed.Message ?? "");
			await Assert.That(relaxed.PathEnd).IsEqualTo(CertificatePathEnd.MissingIssuer);
		}
	}

	// A CA whose name constraints permit a registeredID, a form that the platforms do not support, and an expired leaf below it. Windows and Linux report HasNotSupportedNameConstraint for a leaf with a registeredID, and macOS InvalidNameConstraints for the CA whatever names the leaf has; IgnoreInvalidName leaves out either, and not the expiry.
	[Test]
	[Arguments(true)]
	[Arguments(false)]
	public async Task IgnoreInvalidNameLeavesOutANameConstraintOfAFormThatThePlatformDoesNotSupport(bool registeredIdName)
	{
		using TestPki pki = new(configureIntermediate: static request => request.CertificateExtensions.Add(new X509Extension("2.5.29.30", [0x30, 0x08, 0xA0, 0x06, 0x30, 0x04, 0x88, 0x02, 0x2A, 0x03], true)));
		byte[] alternativeName = registeredIdName ? [0x30, 0x04, 0x88, 0x02, 0x2A, 0x03] : SubjectAlternativeName("a.example").RawData;
		using X509Certificate2 leaf = pki.IssueLeaf(request => request.CertificateExtensions.Add(new X509Extension("2.5.29.17", alternativeName, false)), notAfter: Now.AddDays(-1));
		CertificateValidationContext context = pki.Context(leaf, CertificateUsage.ServerAuthentication);
		X509ChainPolicy policy = pki.Policy();
		CertificateValidationError[] expired = [CertificateValidationError.Expired];
		CertificateValidationError[] expiredAndUnsupported = [CertificateValidationError.Expired, CertificateValidationError.Unspecified];

		CertificateValidationResult strict = await new PlatformCertificateValidator(policy).ValidateAsync(context);
		policy.VerificationFlags = X509VerificationFlags.IgnoreInvalidName;
		CertificateValidationResult relaxed = await new PlatformCertificateValidator(policy).ValidateAsync(context);
		policy.VerificationFlags |= X509VerificationFlags.IgnoreNotTimeValid;
		CertificateValidationResult accepted = await new PlatformCertificateValidator(policy).ValidateAsync(context);

		using (Assert.Multiple())
		{
			await Assert.That(strict.Errors).IsEquivalentTo(registeredIdName || OperatingSystem.IsMacOS() ? expiredAndUnsupported : expired, CollectionOrdering.Matching).Because(strict.Message ?? "");
			await Assert.That(relaxed.Errors).IsEquivalentTo(expired, CollectionOrdering.Matching).Because(relaxed.Message ?? "");
			await Assert.That(accepted.IsValid).IsTrue().Because($"{accepted.Error} {accepted.Message}");
		}
	}

	// IgnoreInvalidName leaves out every status of a name constraint, of the chain and of its certificates, and nothing else.
	[Test]
	[Arguments(X509ChainStatusFlags.InvalidNameConstraints)]
	[Arguments(X509ChainStatusFlags.HasNotSupportedNameConstraint)]
	[Arguments(X509ChainStatusFlags.HasNotDefinedNameConstraint)]
	[Arguments(X509ChainStatusFlags.HasNotPermittedNameConstraint)]
	[Arguments(X509ChainStatusFlags.HasExcludedNameConstraint)]
	public async Task IgnoreInvalidNameLeavesOutEveryNameConstraintStatus(X509ChainStatusFlags status)
	{
		const X509ChainStatusFlags expired = X509ChainStatusFlags.NotTimeValid;
		X509ChainStatusFlags[] elementStatus = [expired, status, X509ChainStatusFlags.NoError];
		X509VerificationFlags[] revocationFlags = [IgnoreEnd, IgnoreAuthority, IgnoreRoot];

		using (Assert.Multiple())
		{
			await Assert.That(PlatformCertificateValidator.ReportedStatuses(status | expired, elementStatus, revocationFlags, X509VerificationFlags.IgnoreInvalidName)).IsEqualTo(expired);
			await Assert.That(PlatformCertificateValidator.ReportedStatuses(status | expired, elementStatus, revocationFlags, X509VerificationFlags.NoFlag)).IsEqualTo(status | expired);
		}
	}

	// Windows reports NoIssuanceChainPolicy where Linux and macOS report NotValidForUsage.
	[Test]
	public async Task ReportsAnIssuancePolicyThatTheChainDoesNotMeetAsNotValidForUsage()
	{
		using TestPki pki = new(configureRoot: static request => request.CertificateExtensions.Add(new X509Extension("2.5.29.36", [0x30, 0x03, 0x80, 0x01, 0x00], true)));
		using X509Certificate2 leaf = pki.IssueLeaf();

		CertificateValidationResult result = await pki.Validator().ValidateAsync(pki.Context(leaf, CertificateUsage.ServerAuthentication));

		await Assert.That(result.Errors).IsEquivalentTo([CertificateValidationError.NotValidForUsage], CollectionOrdering.Matching).Because(result.Message ?? "");
	}

	[Test]
	public async Task ReportsThePathAndWhereItEnds()
	{
		using TestPki pki = new();
		using TestPki other = new();
		using X509Certificate2 leaf = pki.IssueLeaf();
		CertificateValidationContext context = pki.Context(leaf, CertificateUsage.ServerAuthentication);
		CertificateValidationContext withRoot = pki.Context(leaf, CertificateUsage.ServerAuthentication, withRoot: true);
		CertificateValidationContext leafOnly = new([context.PresentedCertificates[0]], CertificateUsage.ServerAuthentication);
		X509ChainPolicy allowUnknown = pki.Policy();
		allowUnknown.VerificationFlags = X509VerificationFlags.AllowUnknownCertificateAuthority;

		CertificateValidationResult trusted = await pki.Validator().ValidateAsync(context);
		CertificateValidationResult untrusted = await new PlatformCertificateValidator(TrustOnly(other.Root)).ValidateAsync(withRoot);
		CertificateValidationResult partial = await pki.Validator().ValidateAsync(leafOnly);
		CertificateValidationResult allowed = await new PlatformCertificateValidator(allowUnknown).ValidateAsync(leafOnly);

		using (Assert.Multiple())
		{
			await Assert.That(trusted.IsValid).IsTrue().Because($"{trusted.Error} {trusted.Message}");
			await Assert.That(trusted.Path).Count().IsEqualTo(3);
			await Assert.That(trusted.Path[0]).IsSameReferenceAs(context.PresentedCertificates[0]);
			await Assert.That(trusted.Path[1]).IsSameReferenceAs(context.PresentedCertificates[1]);
			await Assert.That(trusted.Path[2].Encoded.ToArray()).IsEquivalentTo(pki.Root.RawData, CollectionOrdering.Matching);
			await Assert.That(trusted.PathEnd).IsEqualTo(CertificatePathEnd.TrustAnchor);

			await Assert.That(untrusted.Errors).IsEquivalentTo([CertificateValidationError.UntrustedRoot], CollectionOrdering.Matching);
			await Assert.That(untrusted.Path).IsEquivalentTo(withRoot.PresentedCertificates, CollectionOrdering.Matching);
			await Assert.That(untrusted.PathEnd).IsEqualTo(CertificatePathEnd.UntrustedRoot);

			await Assert.That(partial.Errors).IsEquivalentTo([CertificateValidationError.UntrustedRoot], CollectionOrdering.Matching);
			await Assert.That(partial.Path).IsEquivalentTo(leafOnly.PresentedCertificates, CollectionOrdering.Matching);
			await Assert.That(partial.PathEnd).IsEqualTo(CertificatePathEnd.MissingIssuer);

			// The flag accepts the partial chain, and the path still tells that its end is not a trust anchor.
			await Assert.That(allowed.IsValid).IsTrue().Because($"{allowed.Error} {allowed.Message}");
			await Assert.That(allowed.Path).IsEquivalentTo(leafOnly.PresentedCertificates, CollectionOrdering.Matching);
			await Assert.That(allowed.PathEnd).IsEqualTo(CertificatePathEnd.MissingIssuer);
		}
	}

	[Test]
	public async Task ChecksTheHostNameWhenTheChainFails()
	{
		using TestPki pki = new();
		using TestPki other = new();
		using X509Certificate2 leaf = pki.IssueLeaf(static request => request.CertificateExtensions.Add(SubjectAlternativeName("example.com")));
		using X509Certificate2 expired = pki.IssueLeaf(static request => request.CertificateExtensions.Add(SubjectAlternativeName("example.com")), notAfter: Now.AddDays(-1));
		PlatformCertificateValidator validator = new(TrustOnly(other.Root));

		CertificateValidationResult named = await validator.ValidateAsync(pki.Context(leaf, CertificateUsage.ServerAuthentication, "example.com", withRoot: true));
		CertificateValidationResult misnamed = await validator.ValidateAsync(pki.Context(leaf, CertificateUsage.ServerAuthentication, "other.com", withRoot: true));
		CertificateValidationResult expiredAndMisnamed = await validator.ValidateAsync(pki.Context(expired, CertificateUsage.ServerAuthentication, "other.com", withRoot: true));

		using (Assert.Multiple())
		{
			await Assert.That(named.Errors).IsEquivalentTo([CertificateValidationError.UntrustedRoot], CollectionOrdering.Matching);
			await Assert.That(misnamed.Errors).IsEquivalentTo([CertificateValidationError.UntrustedRoot, CertificateValidationError.NameMismatch], CollectionOrdering.Matching);
			await Assert.That(misnamed.Error).IsEqualTo(CertificateValidationError.UntrustedRoot);
			await Assert.That(expiredAndMisnamed.Errors).IsEquivalentTo([CertificateValidationError.Expired, CertificateValidationError.UntrustedRoot, CertificateValidationError.NameMismatch], CollectionOrdering.Matching);
		}
	}

	// With a host name, the validator reads the names and reports the extension; without one, the platform alone judges the leaf, and Linux reports it as a partial chain where the other platforms accept it.
	[Test]
	public async Task ReportsASubjectAlternativeNameThatDoesNotDecodeAsMalformed()
	{
		using TestPki pki = new();
		using TestPki other = new();
		using X509Certificate2 leaf = pki.IssueLeaf(static request => request.CertificateExtensions.Add(new X509Extension("2.5.29.17", [0x30, 0x03, 0x82, 0x05, 0x61], false)));

		using (Assert.Multiple())
		{
			CertificateValidationResult named = await pki.Validator().ValidateAsync(pki.Context(leaf, CertificateUsage.ServerAuthentication, "a.example"));

			await Assert.That(named.Error).IsEqualTo(CertificateValidationError.Malformed).Because(named.Message ?? "");
			await Assert.That(named.Errors).DoesNotContain(CertificateValidationError.NameMismatch);

			CertificateValidationResult unnamed = await pki.Validator().ValidateAsync(pki.Context(leaf, CertificateUsage.ServerAuthentication));

			await Assert.That(unnamed.Errors).DoesNotContain(CertificateValidationError.Malformed).Because(unnamed.Message ?? "");
			await Assert.That(unnamed.IsValid).IsEqualTo(!OperatingSystem.IsLinux()).Because(unnamed.Message ?? "");

			CertificateValidationResult untrusted = await new PlatformCertificateValidator(TrustOnly(other.Root)).ValidateAsync(pki.Context(leaf, CertificateUsage.ServerAuthentication, "a.example", withRoot: true));

			await Assert.That(untrusted.Error).IsEqualTo(CertificateValidationError.Malformed);
			await Assert.That(untrusted.Errors).Contains(CertificateValidationError.UntrustedRoot);
		}
	}

	// A key usage BIT STRING with a trailing zero bit, as a few system roots have, which DER forbids and the platforms and Certificate.Decode accept.
	[Test]
	public async Task AcceptsAPathThroughARootWithTrailingKeyUsageBits()
	{
		using ECDsa rootKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
		CertificateRequest rootRequest = new($"CN=BER Root {Guid.NewGuid():N}", rootKey, HashAlgorithmName.SHA256);
		rootRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
		rootRequest.CertificateExtensions.Add(new X509Extension("2.5.29.15", [0x03, 0x02, 0x00, 0x06], true));
		using X509Certificate2 root = rootRequest.CreateSelfSigned(Now.AddDays(-2), Now.AddDays(2));
		using ECDsa leafKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
		CertificateRequest leafRequest = new("CN=Leaf", leafKey, HashAlgorithmName.SHA256);
		leafRequest.CertificateExtensions.Add(EnhancedKeyUsage(ServerAuthenticationOid));
		using X509Certificate2 leaf = leafRequest.Create(root.SubjectName, X509SignatureGenerator.CreateForECDsa(rootKey), Now.AddDays(-1), Now.AddDays(1), [1]);

		CertificateValidationResult result = await new PlatformCertificateValidator(TrustOnly(root)).ValidateAsync(new CertificateValidationContext([Certificate.Decode(leaf.RawData)], CertificateUsage.ServerAuthentication));

		using (Assert.Multiple())
		{
			await Assert.That(Certificate.Decode(root.RawData).KeyUsage).IsEqualTo(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign);
			await Assert.That(result.IsValid).IsTrue().Because(result.Message ?? "");
			await Assert.That(result.Path.Select(static certificate => Convert.ToHexString(certificate.Encoded.Span))).IsEquivalentTo([Convert.ToHexString(leaf.RawData), Convert.ToHexString(root.RawData)], CollectionOrdering.Matching);
			await Assert.That(result.PathEnd).IsEqualTo(CertificatePathEnd.TrustAnchor);
		}
	}

	// A key usage with bit 9 set, which X.509 does not define: the platforms accept the root, and Certificate.Decode rejects it, so the result keeps the platform's decision without a path.
	[Test]
	public async Task KeepsThePlatformsDecisionForAPathWhoseCertificateDoesNotDecode()
	{
		using ECDsa rootKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
		CertificateRequest rootRequest = new($"CN=Undecodable Root {Guid.NewGuid():N}", rootKey, HashAlgorithmName.SHA256);
		rootRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
		rootRequest.CertificateExtensions.Add(new X509Extension("2.5.29.15", [0x03, 0x03, 0x06, 0x06, 0x40], true));
		using X509Certificate2 root = rootRequest.CreateSelfSigned(Now.AddDays(-2), Now.AddDays(2));
		using ECDsa leafKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
		CertificateRequest leafRequest = new("CN=Leaf", leafKey, HashAlgorithmName.SHA256);
		leafRequest.CertificateExtensions.Add(EnhancedKeyUsage(ServerAuthenticationOid));
		using X509Certificate2 leaf = leafRequest.Create(root.SubjectName, X509SignatureGenerator.CreateForECDsa(rootKey), Now.AddDays(-1), Now.AddDays(1), [1]);

		CertificateValidationResult result = await new PlatformCertificateValidator(TrustOnly(root)).ValidateAsync(new CertificateValidationContext([Certificate.Decode(leaf.RawData)], CertificateUsage.ServerAuthentication));

		using (Assert.Multiple())
		{
			await Assert.That(() => Certificate.Decode(root.RawData)).Throws<ArgumentException>();
			await Assert.That(result.IsValid).IsTrue().Because(result.Message ?? "");
			await Assert.That(result.Path).IsEmpty();
			await Assert.That(result.PathEnd).IsEqualTo(CertificatePathEnd.None);
		}
	}

	[Test]
	public async Task ReportsAChainThatThePlatformFailsToBuildAsUnsupported()
	{
		if (!OperatingSystem.IsWindows())
		{
			Skip.Test("Windows alone fails to build a chain with a DSA signature.");
		}

		using DSA rootKey = DSA.Create(2048);
		DsaSignatureGenerator generator = new(rootKey);
		CertificateRequest rootRequest = new(new X500DistinguishedName($"CN=DSA Root {Guid.NewGuid():N}"), generator.PublicKey, HashAlgorithmName.SHA256);
		rootRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
		using X509Certificate2 root = rootRequest.Create(rootRequest.SubjectName, generator, Now.AddDays(-2), Now.AddDays(2), [1]);
		using ECDsa leafKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
		CertificateRequest leafRequest = new("CN=Leaf", leafKey, HashAlgorithmName.SHA256);
		leafRequest.CertificateExtensions.Add(SubjectAlternativeName("dsa.example"));
		using X509Certificate2 leaf = leafRequest.Create(root.SubjectName, generator, Now.AddDays(-1), Now.AddDays(1), [2]);

		CertificateValidationResult result = await new PlatformCertificateValidator(TrustOnly(root)).ValidateAsync(new CertificateValidationContext([Certificate.Decode(leaf.RawData)], CertificateUsage.ServerAuthentication) { HostName = "other.example" });

		using (Assert.Multiple())
		{
			await Assert.That(result.Errors).IsEquivalentTo([CertificateValidationError.UnsupportedAlgorithm, CertificateValidationError.NameMismatch], CollectionOrdering.Matching).Because(result.Message ?? "");
			await Assert.That(result.PathEnd).IsEqualTo(CertificatePathEnd.None);
		}
	}

	// Once the deadline has passed, nothing is retrieved: the server would see a connection otherwise, and the build would wait for it.
	[Test]
	public async Task RetrievesNothingOnceTheDeadlineHasPassed()
	{
		using SilentServer server = new();
		using TestPki pki = new();
		using X509Certificate2 leaf = pki.IssueLeaf(request =>
		{
			request.CertificateExtensions.Add(CertificateRevocationListBuilder.BuildCrlDistributionPointExtension([server.Url("leaf.crl")]));
			request.CertificateExtensions.Add(new X509AuthorityInformationAccessExtension([server.Url("ocsp")], [server.Url("intermediate.cer")]));
		});
		X509ChainPolicy policy = pki.Policy();
		policy.RevocationMode = X509RevocationMode.Online;
		policy.DisableCertificateDownloads = false;
		X509ChainPolicy ignoringRevocation = policy.Clone();
		ignoringRevocation.VerificationFlags = X509VerificationFlags.IgnoreEndRevocationUnknown | X509VerificationFlags.IgnoreCertificateAuthorityRevocationUnknown;
		FixedTimeProvider clock = new(Now);
		// Less than a millisecond counts as none.
		CertificateValidationContext passed = new(pki.Context(leaf, CertificateUsage.ServerAuthentication).PresentedCertificates, CertificateUsage.ServerAuthentication) { Deadline = Now.AddTicks(TimeSpan.TicksPerMillisecond - 1), TimeProvider = clock };
		CertificateValidationContext leafOnly = new([passed.PresentedCertificates[0]], CertificateUsage.ServerAuthentication) { Deadline = Now.AddSeconds(-1), TimeProvider = clock };

		CertificateValidationResult revocation = await new PlatformCertificateValidator(policy).ValidateAsync(passed);
		CertificateValidationResult ignored = await new PlatformCertificateValidator(ignoringRevocation).ValidateAsync(passed);
		CertificateValidationResult download = await new PlatformCertificateValidator(policy).ValidateAsync(leafOnly);

		using (Assert.Multiple())
		{
			await Assert.That(revocation.Errors).IsEquivalentTo([CertificateValidationError.RevocationUnknown], CollectionOrdering.Matching).Because(revocation.Message ?? "");
			await Assert.That(revocation.PathEnd).IsEqualTo(CertificatePathEnd.TrustAnchor);
			await Assert.That(ignored.IsValid).IsTrue().Because($"{ignored.Error} {ignored.Message}");
			await Assert.That(download.Errors).IsEquivalentTo([CertificateValidationError.UntrustedRoot, CertificateValidationError.RevocationUnknown], CollectionOrdering.Matching).Because(download.Message ?? "");
			await Assert.That(download.PathEnd).IsEqualTo(CertificatePathEnd.MissingIssuer);
			await Assert.That(server.Connections).IsEqualTo(0);
		}
	}

	// The deadline bounds each retrieval from the silent server, which would otherwise wait for the platform's own timeout.
	[Test]
	public async Task ShortensEachRetrievalToTheDeadline()
	{
		using SilentServer server = new();
		using TestPki pki = new();
		using X509Certificate2 leaf = pki.IssueLeaf(request => request.CertificateExtensions.Add(new X509AuthorityInformationAccessExtension([server.Url("ocsp")], null)));
		X509ChainPolicy policy = pki.Policy();
		policy.RevocationMode = X509RevocationMode.Online;
		policy.RevocationFlag = X509RevocationFlag.EndCertificateOnly;
		CertificateValidationContext context = new(pki.Context(leaf, CertificateUsage.ServerAuthentication).PresentedCertificates, CertificateUsage.ServerAuthentication) { Deadline = Now.AddMilliseconds(500), TimeProvider = new FixedTimeProvider(Now) };

		Stopwatch stopwatch = Stopwatch.StartNew();
		CertificateValidationResult result = await new PlatformCertificateValidator(policy).ValidateAsync(context);
		stopwatch.Stop();

		using (Assert.Multiple())
		{
			await Assert.That(result.Errors).IsEquivalentTo([CertificateValidationError.RevocationUnknown], CollectionOrdering.Matching).Because(result.Message ?? "");
			await Assert.That(stopwatch.Elapsed).IsLessThan(TimeSpan.FromSeconds(10));
		}
	}

	[Test]
	public async Task LimitsRetrievalsToTheTimeLeft()
	{
		X509ChainPolicy unset = new();
		X509ChainPolicy longer = new() { UrlRetrievalTimeout = TimeSpan.FromSeconds(30) };
		X509ChainPolicy shorter = new() { UrlRetrievalTimeout = TimeSpan.FromSeconds(1) };
		X509ChainPolicy farOff = new();
		X509ChainPolicy online = new() { RevocationMode = X509RevocationMode.Online, DisableCertificateDownloads = false, UrlRetrievalTimeout = TimeSpan.FromSeconds(3) };
		X509ChainPolicy offline = new() { RevocationMode = X509RevocationMode.Offline };
		X509ChainPolicy downloads = new() { RevocationMode = X509RevocationMode.NoCheck, DisableCertificateDownloads = false };
		X509ChainPolicy noDeadline = new() { RevocationMode = X509RevocationMode.Online };

		using (Assert.Multiple())
		{
			await Assert.That(PlatformCertificateValidator.RetrievalLimit(null, Now)).IsNull();
			await Assert.That(PlatformCertificateValidator.RetrievalLimit(Now.AddTicks(15_999), Now)).IsEqualTo(TimeSpan.FromMilliseconds(1));
			await Assert.That(PlatformCertificateValidator.RetrievalLimit(Now.AddTicks(9_999), Now)).IsEqualTo(TimeSpan.Zero);
			await Assert.That(PlatformCertificateValidator.RetrievalLimit(Now.AddDays(-1), Now)).IsEqualTo(TimeSpan.Zero);
			await Assert.That(PlatformCertificateValidator.RetrievalLimit(DateTimeOffset.MaxValue, DateTimeOffset.MinValue)).IsEqualTo(TimeSpan.FromMilliseconds((DateTimeOffset.MaxValue - DateTimeOffset.MinValue).Ticks / TimeSpan.TicksPerMillisecond));

			// Zero stands for the platform's default timeout, which the time left shortens.
			await Assert.That(PlatformCertificateValidator.ApplyRetrievalLimit(unset, TimeSpan.FromSeconds(2))).IsFalse();
			await Assert.That(unset.UrlRetrievalTimeout).IsEqualTo(TimeSpan.FromSeconds(2));
			await Assert.That(PlatformCertificateValidator.ApplyRetrievalLimit(longer, TimeSpan.FromSeconds(2))).IsFalse();
			await Assert.That(longer.UrlRetrievalTimeout).IsEqualTo(TimeSpan.FromSeconds(2));
			await Assert.That(PlatformCertificateValidator.ApplyRetrievalLimit(shorter, TimeSpan.FromSeconds(2))).IsFalse();
			await Assert.That(shorter.UrlRetrievalTimeout).IsEqualTo(TimeSpan.FromSeconds(1));
			await Assert.That(PlatformCertificateValidator.ApplyRetrievalLimit(farOff, TimeSpan.FromSeconds(20))).IsFalse();
			await Assert.That(farOff.UrlRetrievalTimeout).IsEqualTo(TimeSpan.Zero);

			// Windows reads a timeout below a millisecond as zero, the default, so it becomes a millisecond.
			X509ChainPolicy subMillisecond = new() { UrlRetrievalTimeout = TimeSpan.FromTicks(5_000) };
			await Assert.That(PlatformCertificateValidator.ApplyRetrievalLimit(subMillisecond, TimeSpan.FromMilliseconds(500))).IsFalse();
			await Assert.That(subMillisecond.UrlRetrievalTimeout).IsEqualTo(TimeSpan.FromMilliseconds(1));

			// No time left: no retrieval at all, and the revocation check, offline too, is skipped.
			await Assert.That(PlatformCertificateValidator.ApplyRetrievalLimit(online, TimeSpan.Zero)).IsTrue();
			await Assert.That(online.RevocationMode).IsEqualTo(X509RevocationMode.NoCheck);
			await Assert.That(online.DisableCertificateDownloads).IsTrue();
			await Assert.That(online.UrlRetrievalTimeout).IsEqualTo(TimeSpan.FromSeconds(3));
			await Assert.That(PlatformCertificateValidator.ApplyRetrievalLimit(offline, TimeSpan.Zero)).IsTrue();
			await Assert.That(offline.RevocationMode).IsEqualTo(X509RevocationMode.NoCheck);
			await Assert.That(PlatformCertificateValidator.ApplyRetrievalLimit(downloads, TimeSpan.Zero)).IsFalse();
			await Assert.That(downloads.DisableCertificateDownloads).IsTrue();
			await Assert.That(PlatformCertificateValidator.ApplyRetrievalLimit(noDeadline, null)).IsFalse();
			await Assert.That(noDeadline.RevocationMode).IsEqualTo(X509RevocationMode.Online);
			await Assert.That(noDeadline.UrlRetrievalTimeout).IsEqualTo(TimeSpan.Zero);
		}
	}

	// Windows takes the last certificate of a complete path for the root; Linux and macOS every certificate after the peer's whose issuer is its subject. SelfIssued gives that of each certificate, from the peer's.
	public static IEnumerable<Func<(bool Windows, bool[] SelfIssued, bool Complete, X509VerificationFlags[] Expected)>> RevocationFlagCases()
	{
		yield return () => (true, [false, false, true], true, [IgnoreEnd, IgnoreAuthority, IgnoreRoot]);
		yield return () => (true, [false, false, false], false, [IgnoreEnd, IgnoreAuthority, IgnoreAuthority]);
		yield return () => (true, [false, true, true], true, [IgnoreEnd, IgnoreAuthority, IgnoreRoot]);
		yield return () => (true, [false, true], false, [IgnoreEnd, IgnoreAuthority]);
		yield return () => (true, [false, false], true, [IgnoreEnd, IgnoreRoot]);
		yield return () => (true, [true], true, [IgnoreEnd]);
		yield return () => (false, [false, false, true], true, [IgnoreEnd, IgnoreAuthority, IgnoreRoot]);
		yield return () => (false, [false, false, false], false, [IgnoreEnd, IgnoreAuthority, IgnoreAuthority]);
		yield return () => (false, [false, true, true], true, [IgnoreEnd, IgnoreRoot, IgnoreRoot]);
		yield return () => (false, [false, false, true, true], true, [IgnoreEnd, IgnoreAuthority, IgnoreRoot, IgnoreRoot]);
		yield return () => (false, [false, true], false, [IgnoreEnd, IgnoreRoot]);
		yield return () => (false, [false, false], true, [IgnoreEnd, IgnoreAuthority]);
		yield return () => (false, [true], true, [IgnoreEnd]);
	}

	[Test]
	[MethodDataSource(nameof(RevocationFlagCases))]
	public async Task AssignsTheRevocationFlagsAsThePlatformDoes(bool windows, bool[] selfIssued, bool complete, X509VerificationFlags[] expected)
	{
		X509VerificationFlags[] revocationFlags = PlatformCertificateValidator.GetRevocationUnknownFlags(selfIssued, complete, windows);

		await Assert.That(revocationFlags).IsEquivalentTo(expected, CollectionOrdering.Matching);
	}

	// The cases that the platforms do not produce: a revocation status of the chain alone, and one of the root.
	[Test]
	public async Task IgnoresRevocationStatusesPerCertificate()
	{
		const X509ChainStatusFlags unknown = X509ChainStatusFlags.RevocationStatusUnknown | X509ChainStatusFlags.OfflineRevocation;
		X509ChainStatusFlags[] leafAndIntermediate = [unknown, unknown, X509ChainStatusFlags.NoError];
		X509ChainStatusFlags[] rootOnly = [X509ChainStatusFlags.NoError, X509ChainStatusFlags.NoError, unknown];
		X509ChainStatusFlags[] none = [X509ChainStatusFlags.NoError, X509ChainStatusFlags.NoError];
		X509VerificationFlags[] path = [IgnoreEnd, IgnoreAuthority, IgnoreRoot];
		X509VerificationFlags[] partial = [IgnoreEnd, IgnoreAuthority, IgnoreAuthority];
		X509VerificationFlags[] rollover = [IgnoreEnd, IgnoreRoot, IgnoreRoot];

		using (Assert.Multiple())
		{
			await Assert.That(PlatformCertificateValidator.ReportedStatuses(unknown, leafAndIntermediate, path, IgnoreEnd)).IsEqualTo(unknown);
			await Assert.That(PlatformCertificateValidator.ReportedStatuses(unknown, leafAndIntermediate, path, IgnoreEnd | IgnoreAuthority)).IsEqualTo(X509ChainStatusFlags.NoError);
			await Assert.That(PlatformCertificateValidator.ReportedStatuses(unknown, rootOnly, path, IgnoreEnd | IgnoreAuthority)).IsEqualTo(unknown);
			await Assert.That(PlatformCertificateValidator.ReportedStatuses(unknown, rootOnly, path, IgnoreRoot)).IsEqualTo(X509ChainStatusFlags.NoError);

			// Each certificate by its own flag, whatever its place.
			await Assert.That(PlatformCertificateValidator.ReportedStatuses(unknown, rootOnly, partial, IgnoreRoot)).IsEqualTo(unknown);
			await Assert.That(PlatformCertificateValidator.ReportedStatuses(unknown, rootOnly, partial, IgnoreAuthority)).IsEqualTo(X509ChainStatusFlags.NoError);
			await Assert.That(PlatformCertificateValidator.ReportedStatuses(unknown, leafAndIntermediate, rollover, IgnoreEnd | IgnoreAuthority)).IsEqualTo(unknown);
			await Assert.That(PlatformCertificateValidator.ReportedStatuses(unknown, leafAndIntermediate, rollover, IgnoreEnd | IgnoreRoot)).IsEqualTo(X509ChainStatusFlags.NoError);

			await Assert.That(PlatformCertificateValidator.ReportedStatuses(unknown, none, path, IgnoreEnd | IgnoreAuthority)).IsEqualTo(unknown);
			await Assert.That(PlatformCertificateValidator.ReportedStatuses(unknown, none, path, IgnoreEnd | IgnoreAuthority | IgnoreRoot)).IsEqualTo(X509ChainStatusFlags.NoError);
			await Assert.That(PlatformCertificateValidator.ReportedStatuses(unknown | X509ChainStatusFlags.UntrustedRoot, leafAndIntermediate, path, IgnoreEnd | IgnoreAuthority)).IsEqualTo(X509ChainStatusFlags.UntrustedRoot);
		}
	}

	[Test]
	public async Task CountsTheRevocationChecksThatTheDeadlineSkipped()
	{
		X509VerificationFlags[] path = [IgnoreEnd, IgnoreAuthority, IgnoreRoot];
		X509VerificationFlags[] rollover = [IgnoreEnd, IgnoreRoot, IgnoreRoot];

		using (Assert.Multiple())
		{
			await Assert.That(PlatformCertificateValidator.SkippedRevocationMatters(path, true, X509RevocationFlag.ExcludeRoot, X509VerificationFlags.NoFlag)).IsTrue();
			await Assert.That(PlatformCertificateValidator.SkippedRevocationMatters(path, true, X509RevocationFlag.ExcludeRoot, IgnoreEnd)).IsTrue();
			await Assert.That(PlatformCertificateValidator.SkippedRevocationMatters(path, true, X509RevocationFlag.EntireChain, IgnoreEnd | IgnoreAuthority)).IsFalse();
			await Assert.That(PlatformCertificateValidator.SkippedRevocationMatters(path, true, X509RevocationFlag.EndCertificateOnly, IgnoreEnd)).IsFalse();

			// An issuer by the flag that the platform applies to it.
			await Assert.That(PlatformCertificateValidator.SkippedRevocationMatters(rollover, true, X509RevocationFlag.ExcludeRoot, IgnoreEnd | IgnoreAuthority)).IsTrue();
			await Assert.That(PlatformCertificateValidator.SkippedRevocationMatters(rollover, true, X509RevocationFlag.ExcludeRoot, IgnoreEnd | IgnoreRoot)).IsFalse();

			// The root is not counted, nor is a self-signed certificate of the peer taken for one.
			await Assert.That(PlatformCertificateValidator.SkippedRevocationMatters([IgnoreEnd, IgnoreRoot], true, X509RevocationFlag.EntireChain, IgnoreEnd)).IsFalse();
			await Assert.That(PlatformCertificateValidator.SkippedRevocationMatters([IgnoreEnd], true, X509RevocationFlag.EntireChain, IgnoreAuthority)).IsTrue();
			await Assert.That(PlatformCertificateValidator.SkippedRevocationMatters([IgnoreEnd], true, X509RevocationFlag.EntireChain, IgnoreEnd)).IsFalse();

			// The last certificate of a partial chain is an issuer.
			await Assert.That(PlatformCertificateValidator.SkippedRevocationMatters([IgnoreEnd, IgnoreAuthority], false, X509RevocationFlag.ExcludeRoot, IgnoreEnd)).IsTrue();
			await Assert.That(PlatformCertificateValidator.SkippedRevocationMatters([IgnoreEnd], false, X509RevocationFlag.ExcludeRoot, IgnoreEnd)).IsFalse();
		}
	}

	// A trusted root, a CA certificate that rolls over its key and whose issuer is therefore its subject, and an expired leaf; an offline revocation check finds no CRL, so the status of each certificate checked is unknown.
	// Windows checks the CA certificate only below a root that it does not trust, and takes it for a CA; Linux checks it and takes it for a root; macOS checks the leaf alone offline.
	public static IEnumerable<Func<(bool Trusted, X509VerificationFlags Flags, CertificateValidationError[] Windows, CertificateValidationError[] Linux, CertificateValidationError[] MacOS)>> KeyRolloverCases()
	{
		const CertificateValidationError expired = CertificateValidationError.Expired;
		const CertificateValidationError unknown = CertificateValidationError.RevocationUnknown;
		const X509VerificationFlags untrusted = X509VerificationFlags.AllowUnknownCertificateAuthority;

		yield return () => (true, IgnoreEnd | IgnoreAuthority, [expired], [expired, unknown], [expired]);
		yield return () => (true, IgnoreEnd | IgnoreRoot, [expired], [expired], [expired]);
		yield return () => (true, IgnoreEnd | IgnoreAuthority | X509VerificationFlags.IgnoreNotTimeValid, [], [unknown], []);
		yield return () => (true, IgnoreEnd | IgnoreRoot | X509VerificationFlags.IgnoreNotTimeValid, [], [], []);
		yield return () => (false, untrusted | IgnoreEnd | IgnoreAuthority, [expired], [expired, unknown], [expired]);
		yield return () => (false, untrusted | IgnoreEnd | IgnoreRoot, [expired, unknown], [expired], [expired]);
	}

	[Test]
	[MethodDataSource(nameof(KeyRolloverCases))]
	public async Task IgnoresTheRevocationStatusOfACertificateWhoseIssuerIsItsSubjectAsThePlatformDoes(bool trusted, X509VerificationFlags flags, CertificateValidationError[] windows, CertificateValidationError[] linux, CertificateValidationError[] macOS)
	{
		CertificateValidationError[] expected = OperatingSystem.IsWindows() ? windows : OperatingSystem.IsMacOS() ? macOS : linux;
		using KeyRolloverPki pki = new();
		using TestPki other = new();
		X509ChainPolicy policy = trusted ? TrustOnly(pki.Root) : TrustOnly(other.Root);
		policy.RevocationMode = X509RevocationMode.Offline;
		policy.VerificationFlags = flags;

		CertificateValidationResult result = await new PlatformCertificateValidator(policy).ValidateAsync(pki.Context(withRoot: !trusted));

		using (Assert.Multiple())
		{
			await Assert.That(result.Errors).IsEquivalentTo(expected, CollectionOrdering.Matching).Because(result.Message ?? "");
			await Assert.That(result.Path).Count().IsEqualTo(3);
			await Assert.That(result.PathEnd).IsEqualTo(trusted ? CertificatePathEnd.TrustAnchor : CertificatePathEnd.UntrustedRoot);
		}
	}

	// A revocation check that the deadline skipped counts the CA certificate that rolls over the root's key as the platform would: Windows as a CA, and Linux and macOS as a root.
	[Test]
	public async Task CountsASkippedRevocationCheckOfACertificateWhoseIssuerIsItsSubjectAsThePlatformDoes()
	{
		using KeyRolloverPki pki = new(expiredLeaf: false);
		X509ChainPolicy authority = TrustOnly(pki.Root);
		authority.RevocationMode = X509RevocationMode.Online;
		authority.VerificationFlags = IgnoreEnd | IgnoreAuthority;
		X509ChainPolicy root = authority.Clone();
		root.VerificationFlags = IgnoreEnd | IgnoreRoot;
		CertificateValidationContext passed = new(pki.Context(withRoot: false).PresentedCertificates, CertificateUsage.ServerAuthentication) { Deadline = Now.AddSeconds(-1), TimeProvider = new FixedTimeProvider(Now) };

		CertificateValidationError[] unknown = [CertificateValidationError.RevocationUnknown];

		CertificateValidationResult ignoringAuthorities = await new PlatformCertificateValidator(authority).ValidateAsync(passed);
		CertificateValidationResult ignoringRoots = await new PlatformCertificateValidator(root).ValidateAsync(passed);

		using (Assert.Multiple())
		{
			await Assert.That(ignoringAuthorities.Errors).IsEquivalentTo(OperatingSystem.IsWindows() ? [] : unknown, CollectionOrdering.Matching).Because(ignoringAuthorities.Message ?? "");
			await Assert.That(ignoringRoots.Errors).IsEquivalentTo(OperatingSystem.IsWindows() ? unknown : [], CollectionOrdering.Matching).Because(ignoringRoots.Message ?? "");
		}
	}

	private static async Task AssertError(CertificateValidationResult result, CertificateValidationError error)
	{
		await Assert.That(result.IsValid).IsFalse();
		await Assert.That(result.Error).IsEqualTo(error).Because(result.Message ?? "");
	}

	// A root and an intermediate CA, and leaves that the intermediate issues for server authentication by default. The issuers sign through generators, which let a validity period outlast the issuer's.
	private sealed class TestPki : IDisposable
	{
		private readonly ECDsa _rootKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
		private readonly ECDsa _intermediateKey = ECDsa.Create(ECCurve.NamedCurves.nistP384);

		public TestPki(Action<CertificateRequest>? configureRoot = null, Action<CertificateRequest>? configureIntermediate = null, bool intermediateIsCa = true, DateTimeOffset? intermediateNotAfter = null)
		{
			string unique = Guid.NewGuid().ToString("N");
			CertificateRequest rootRequest = new($"CN=Test Root {unique}", _rootKey, HashAlgorithmName.SHA256);
			rootRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
			rootRequest.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
			configureRoot?.Invoke(rootRequest);
			Root = rootRequest.CreateSelfSigned(Now.AddDays(-10), Now.AddDays(10));

			CertificateRequest intermediateRequest = new($"CN=Test Intermediate {unique}", _intermediateKey, HashAlgorithmName.SHA384);
			intermediateRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(intermediateIsCa, intermediateIsCa, 0, true));
			intermediateRequest.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
			configureIntermediate?.Invoke(intermediateRequest);
			DateTimeOffset intermediateEnd = intermediateNotAfter ?? Now.AddDays(9);
			Intermediate = intermediateRequest.Create(Root.SubjectName, X509SignatureGenerator.CreateForECDsa(_rootKey), intermediateEnd.AddDays(-18), intermediateEnd, [1]);
		}

		public X509Certificate2 Root { get; }

		public X509Certificate2 Intermediate { get; }

		public X509Certificate2 IssueLeaf(Action<CertificateRequest>? configure = null, string subject = "CN=Test Leaf", DateTimeOffset? notAfter = null, string eku = ServerAuthenticationOid, X509KeyUsageFlags keyUsage = X509KeyUsageFlags.DigitalSignature)
		{
			using ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
			CertificateRequest request = new(subject, key, HashAlgorithmName.SHA256);
			request.CertificateExtensions.Add(new X509KeyUsageExtension(keyUsage, true));
			request.CertificateExtensions.Add(EnhancedKeyUsage(eku));
			configure?.Invoke(request);
			DateTimeOffset end = notAfter ?? Now.AddDays(8);
			byte[] serialNumber = RandomNumberGenerator.GetBytes(8);
			serialNumber[0] = (byte)(0x40 | serialNumber[0] & 0x3F);
			return request.Create(Intermediate.SubjectName, X509SignatureGenerator.CreateForECDsa(_intermediateKey), notAfter is null ? Now.AddDays(-1) : end.AddDays(-2), end, serialNumber);
		}

		public X509ChainPolicy Policy()
		{
			return TrustOnly(Root);
		}

		public PlatformCertificateValidator Validator()
		{
			return new PlatformCertificateValidator(Policy());
		}

		// The leaf and the intermediate, and the root if withRoot.
		public CertificateValidationContext Context(X509Certificate2 leaf, CertificateUsage usage, string? hostName = null, bool withRoot = false)
		{
			Certificate[] certificates = withRoot ? [Certificate.Decode(leaf.RawData), Certificate.Decode(Intermediate.RawData), Certificate.Decode(Root.RawData)] : [Certificate.Decode(leaf.RawData), Certificate.Decode(Intermediate.RawData)];
			return new CertificateValidationContext(certificates, usage) { HostName = hostName };
		}

		public void Dispose()
		{
			Intermediate.Dispose();
			Root.Dispose();
			_intermediateKey.Dispose();
			_rootKey.Dispose();
		}
	}

	// A root, a CA certificate for a new key of the root's subject, which the root's key signs, and a leaf that the new key issues; the key identifiers tell the platforms which key signed each.
	private sealed class KeyRolloverPki : IDisposable
	{
		public KeyRolloverPki(bool expiredLeaf = true)
		{
			using ECDsa rootKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
			using ECDsa rolloverKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
			using ECDsa leafKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
			string name = $"CN=Key Rollover Root {Guid.NewGuid():N}";

			CertificateRequest rootRequest = new(name, rootKey, HashAlgorithmName.SHA256);
			rootRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
			rootRequest.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
			X509SubjectKeyIdentifierExtension rootKeyIdentifier = new(rootRequest.PublicKey, false);
			rootRequest.CertificateExtensions.Add(rootKeyIdentifier);
			Root = rootRequest.CreateSelfSigned(Now.AddDays(-10), Now.AddDays(10));

			CertificateRequest rolloverRequest = new(name, rolloverKey, HashAlgorithmName.SHA256);
			rolloverRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
			rolloverRequest.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
			X509SubjectKeyIdentifierExtension rolloverKeyIdentifier = new(rolloverRequest.PublicKey, false);
			rolloverRequest.CertificateExtensions.Add(rolloverKeyIdentifier);
			rolloverRequest.CertificateExtensions.Add(X509AuthorityKeyIdentifierExtension.CreateFromSubjectKeyIdentifier(rootKeyIdentifier));
			Rollover = rolloverRequest.Create(Root.SubjectName, X509SignatureGenerator.CreateForECDsa(rootKey), Now.AddDays(-9), Now.AddDays(9), [1]);

			CertificateRequest leafRequest = new("CN=Key Rollover Leaf", leafKey, HashAlgorithmName.SHA256);
			leafRequest.CertificateExtensions.Add(EnhancedKeyUsage(ServerAuthenticationOid));
			leafRequest.CertificateExtensions.Add(X509AuthorityKeyIdentifierExtension.CreateFromSubjectKeyIdentifier(rolloverKeyIdentifier));
			Leaf = leafRequest.Create(Rollover.SubjectName, X509SignatureGenerator.CreateForECDsa(rolloverKey), Now.AddDays(-3), expiredLeaf ? Now.AddDays(-1) : Now.AddDays(8), [2]);
		}

		public X509Certificate2 Root { get; }

		public X509Certificate2 Rollover { get; }

		public X509Certificate2 Leaf { get; }

		// The leaf and the rollover certificate, and the root if withRoot.
		public CertificateValidationContext Context(bool withRoot)
		{
			Certificate[] certificates = withRoot ? [Certificate.Decode(Leaf.RawData), Certificate.Decode(Rollover.RawData), Certificate.Decode(Root.RawData)] : [Certificate.Decode(Leaf.RawData), Certificate.Decode(Rollover.RawData)];
			return new CertificateValidationContext(certificates, CertificateUsage.ServerAuthentication);
		}

		public void Dispose()
		{
			Leaf.Dispose();
			Rollover.Dispose();
			Root.Dispose();
		}
	}

	// A clock that stands still, and cancels a token at one of its calls.
	private sealed class CancelingClock(CancellationTokenSource source, int cancelAt) : TimeProvider
	{
		private int _calls;

		public int Calls => Volatile.Read(ref _calls);

		public override DateTimeOffset GetUtcNow()
		{
			if (Interlocked.Increment(ref _calls) == cancelAt)
			{
				source.Cancel();
			}

			return Now;
		}
	}

	// dsa-with-SHA256 (RFC 5758, Sec. 3.1), which CertificateRequest has no generator for.
	private sealed class DsaSignatureGenerator(DSA key) : X509SignatureGenerator
	{
		public override byte[] GetSignatureAlgorithmIdentifier(HashAlgorithmName hashAlgorithm)
		{
			return [0x30, 0x0B, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x02];
		}

		public override byte[] SignData(byte[] data, HashAlgorithmName hashAlgorithm)
		{
			return key.SignData(data, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence);
		}

		protected override PublicKey BuildPublicKey()
		{
			return PublicKey.CreateFromSubjectPublicKeyInfo(key.ExportSubjectPublicKeyInfo(), out _);
		}
	}
}
