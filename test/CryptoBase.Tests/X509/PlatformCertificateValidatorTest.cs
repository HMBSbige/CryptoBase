using CryptoBase.Abstractions.Signatures;
using CryptoBase.Signatures.Ecdsa;
using CryptoBase.X509;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using static CryptoBase.Tests.X509.X509TestUtils;

namespace CryptoBase.Tests.X509;

[SuppressMessage("ReSharper", "AccessToDisposedClosure")]
public class PlatformCertificateValidatorTest
{
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

		await Assert.That(result.IsValid).IsTrue().Because($"{result.Error} {result.Message}");
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
			await Assert.That(default(CertificateValidationResult).IsValid).IsFalse();
			await Assert.That(CertificateValidationResult.Valid.IsValid).IsTrue();
			await Assert.That(CertificateValidationResult.Invalid(CertificateValidationError.Revoked, "message").Error).IsEqualTo(CertificateValidationError.Revoked);
		}
	}

	private static async Task AssertError(CertificateValidationResult result, CertificateValidationError error)
	{
		await Assert.That(result.IsValid).IsFalse();
		await Assert.That(result.Error).IsEqualTo(error).Because(result.Message ?? "");
	}

	// A root and an intermediate CA, and leaves that the intermediate issues for server authentication by default.
	private sealed class TestPki : IDisposable
	{
		private readonly ECDsa _rootKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
		private readonly ECDsa _intermediateKey = ECDsa.Create(ECCurve.NamedCurves.nistP384);
		private readonly X509Certificate2 _root;

		public TestPki()
		{
			CertificateRequest rootRequest = new("CN=Test Root", _rootKey, HashAlgorithmName.SHA256);
			rootRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
			rootRequest.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
			_root = rootRequest.CreateSelfSigned(Now.AddDays(-10), Now.AddDays(10));

			CertificateRequest intermediateRequest = new("CN=Test Intermediate", _intermediateKey, HashAlgorithmName.SHA384);
			intermediateRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, true, 0, true));
			intermediateRequest.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
			using X509Certificate2 intermediate = intermediateRequest.Create(_root, Now.AddDays(-9), Now.AddDays(9), [1]);
			Intermediate = intermediate.CopyWithPrivateKey(_intermediateKey);
		}

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
			return request.Create(Intermediate, notAfter is null ? Now.AddDays(-1) : end.AddDays(-2), end, serialNumber);
		}

		public X509ChainPolicy Policy()
		{
			return TrustOnly(_root);
		}

		public PlatformCertificateValidator Validator()
		{
			return new PlatformCertificateValidator(Policy());
		}

		public CertificateValidationContext Context(X509Certificate2 leaf, CertificateUsage usage, string? hostName = null)
		{
			return new CertificateValidationContext([Certificate.Decode(leaf.RawData), Certificate.Decode(Intermediate.RawData)], usage) { HostName = hostName };
		}

		public void Dispose()
		{
			Intermediate.Dispose();
			_root.Dispose();
			_intermediateKey.Dispose();
			_rootKey.Dispose();
		}
	}
}
