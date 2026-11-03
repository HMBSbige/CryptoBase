using CryptoBase.Abstractions.Signatures;
using CryptoBase.Signatures;
using CryptoBase.Signatures.Rsa;
using CryptoBase.X509;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Security.Cryptography.X509Certificates;
using static CryptoBase.Tests.X509.X509TestUtils;

namespace CryptoBase.Tests.X509.Limbo;

// Runs every x509-limbo testcase with TrustAnchorCertificateValidator and compares the results with the expected ones and the tolerances.
public class LimboTest
{
	private const string Success = "SUCCESS";
	private const string Failure = "FAILURE";
	private const string Skipped = "SKIPPED";

	// The features that the validator implements; a testcase with any other feature is skipped, whether limbo-schema.json knows it or not.
	// Skipped are has-crl, name-constraint-dn, pedantic-public-suffix-wildcard, pedantic-rfc5280, rfc5280-incompatible-with-webpki, has-policy-constraints, pedantic-serial-number and pedantic-webpki-eku, and the certificate policy features.
	private static readonly HashSet<string> SupportedFeatures = ["max-chain-depth", "denial-of-service", "has-mldsa", "pedantic-webpki-subscriber-key"];

	// The most that a denial-of-service testcase may take, which only a search without limits exceeds; generous for emulated and Debug runs.
	private static readonly TimeSpan DenialOfServiceTimeout = TimeSpan.FromSeconds(30);

	[Test]
	public async Task TestcasesHaveTheExpectedResults()
	{
		IReadOnlyList<LimboTestcase> testcases = LimboTestcases.All;
		ConcurrentDictionary<string, Outcome> outcomes = new();
		Stopwatch stopwatch = Stopwatch.StartNew();

		await Parallel.ForEachAsync(testcases.Where(static testcase => !IsDenialOfService(testcase)), async (testcase, _) => outcomes[testcase.Id] = await EvaluateAsync(testcase, SignatureKey.ImportSubjectPublicKeyInfo));

		// One at a time, so that no other testcase slows them.
		foreach (LimboTestcase testcase in testcases.Where(IsDenialOfService))
		{
			Stopwatch timer = Stopwatch.StartNew();

			try
			{
				outcomes[testcase.Id] = await Task.Run(() => EvaluateAsync(testcase, SignatureKey.ImportSubjectPublicKeyInfo)).WaitAsync(DenialOfServiceTimeout);
			}
			catch (TimeoutException)
			{
				outcomes[testcase.Id] = new Outcome("TIMEOUT", $"The validation took more than {DenialOfServiceTimeout.TotalSeconds} seconds.");
			}

			Console.WriteLine($"{testcase.Id}: {outcomes[testcase.Id].Result} in {timer.Elapsed.TotalMilliseconds:F1} ms");
		}

		stopwatch.Stop();

		int conformant = 0;
		int skipped = 0;
		List<string> tolerated = [];
		List<string> nonconformant = [];
		List<string> stale = [];

		foreach (LimboTestcase testcase in testcases)
		{
			Outcome outcome = outcomes[testcase.Id];
			bool unexpectedSuccess = LimboTolerances.UnexpectedSuccesses.ContainsKey(testcase.Id);
			bool unexpectedFailure = LimboTolerances.UnexpectedFailures.ContainsKey(testcase.Id);
			string line = $"{testcase.Id}: expected {testcase.ExpectedResult}, got {outcome.Result}: {outcome.Detail}";

			if (outcome.Result is Skipped)
			{
				++skipped;

				if (unexpectedSuccess || unexpectedFailure)
				{
					stale.Add($"{testcase.Id} is tolerated, but skipped: {outcome.Detail}");
				}
			}
			else if (outcome.Result == testcase.ExpectedResult)
			{
				++conformant;

				if (unexpectedSuccess || unexpectedFailure)
				{
					stale.Add($"{testcase.Id} is tolerated, but conformant.");
				}
			}
			else if (unexpectedSuccess && outcome.Result is Success || unexpectedFailure && outcome.Result is Failure)
			{
				tolerated.Add(line);
			}
			else
			{
				nonconformant.Add(line);
			}
		}

		int run = testcases.Count - skipped;
		string summary = $"x509-limbo: {testcases.Count} testcases in {stopwatch.Elapsed.TotalSeconds:F1} s: {conformant} conformant, {tolerated.Count + nonconformant.Count} nonconformant ({tolerated.Count} tolerated), {skipped} skipped; {100.0 * conformant / run:F2}% of those run conform.";
		Console.WriteLine(summary);

		foreach (string line in tolerated)
		{
			Console.WriteLine($"tolerated: {line}");
		}

		using (Assert.Multiple())
		{
			await Assert.That(nonconformant).IsEmpty().Because(string.Join(Environment.NewLine, nonconformant.Take(50)));
			await Assert.That(stale).IsEmpty().Because(string.Join(Environment.NewLine, stale));
		}
	}

	// Each tolerated id must name a testcase, so that a misspelled id does not hide a nonconformance, and appear in one table only.
	[Test]
	public async Task ToleratedTestcasesExist()
	{
		HashSet<string> ids = [.. LimboTestcases.All.Select(static testcase => testcase.Id)];
		string[] tolerated = [.. LimboTolerances.UnexpectedSuccesses.Keys, .. LimboTolerances.UnexpectedFailures.Keys];

		using (Assert.Multiple())
		{
			await Assert.That(tolerated.Where(id => !ids.Contains(id))).IsEmpty();
			await Assert.That(tolerated).HasDistinctItems();
			await Assert.That(LimboTolerances.UnexpectedSuccesses.Values.Concat(LimboTolerances.UnexpectedFailures.Values)).All(static reason => reason.Length > 0);
		}
	}

	// The testcases with an RSA key have the same outcomes with RsaKey, which SignatureKey imports, as with PlatformRsaKey, to which an importer without RSA leaves the keys.
	[Test]
	public async Task RsaTestcasesHaveTheSameOutcomesWithPlatformRsaKey()
	{
		LimboTestcase[] testcases = [.. LimboTestcases.All.Where(static testcase => !IsDenialOfService(testcase) && HasRsaKey(testcase))];
		ConcurrentDictionary<string, string> differences = new();

		await Parallel.ForEachAsync(testcases, async (testcase, _) =>
		{
			Outcome core = await EvaluateAsync(testcase, SignatureKey.ImportSubjectPublicKeyInfo);
			Outcome platform = await EvaluateAsync(testcase, ImportWithoutRsa);

			if (core != platform)
			{
				differences[testcase.Id] = $"RsaKey: {core.Result}, {core.Detail}; PlatformRsaKey: {platform.Result}, {platform.Detail}";
			}
		});

		Console.WriteLine($"x509-limbo: {testcases.Length} testcases with an RSA key.");

		using (Assert.Multiple())
		{
			await Assert.That(testcases).IsNotEmpty();
			await Assert.That(differences).IsEmpty().Because(string.Join(Environment.NewLine, differences.Select(static difference => $"{difference.Key}: {difference.Value}")));
		}

		static ISignatureKey ImportWithoutRsa(ReadOnlySpan<byte> subjectPublicKeyInfo)
		{
			ISignatureKey key = SignatureKey.ImportSubjectPublicKeyInfo(subjectPublicKeyInfo);

			if (key is RsaKey)
			{
				key.Dispose();
				throw new NotSupportedException("No RSA.");
			}

			return key;
		}
	}

	private static bool IsDenialOfService(LimboTestcase testcase)
	{
		return testcase.Features.Contains("denial-of-service") || testcase.Id.StartsWith("pathological::", StringComparison.Ordinal);
	}

	// Whether a certificate of the testcase that decodes has an rsaEncryption or id-RSASSA-PSS key.
	private static bool HasRsaKey(LimboTestcase testcase)
	{
		return testcase.TrustedCerts.Concat(testcase.UntrustedIntermediates).Append(testcase.PeerCertificate).Any(static pem =>
		{
			try
			{
				return Certificate.DecodePem(pem).PublicKeyInfo.Algorithm.Oid is "1.2.840.113549.1.1.1" or "1.2.840.113549.1.1.10";
			}
			catch (ArgumentException)
			{
				return false;
			}
		});
	}

	private static async Task<Outcome> EvaluateAsync(LimboTestcase testcase, Func<ReadOnlySpan<byte>, ISignatureKey> importPublicKey)
	{
		if (testcase.Features.FirstOrDefault(static feature => !SupportedFeatures.Contains(feature)) is { } feature)
		{
			return new Outcome(Skipped, $"The feature {feature} is not supported.");
		}

		if (testcase.SignatureAlgorithms.Length > 0 || testcase.Crls.Length > 0)
		{
			return new Outcome(Skipped, "Constraints on signature algorithms and CRLs are not supported.");
		}

		(CertificateUsage usage, string purpose) = testcase.ValidationKind switch
		{
			"SERVER" => (CertificateUsage.ServerAuthentication, "serverAuth"),
			"CLIENT" => (CertificateUsage.ClientAuthentication, "clientAuth"),
			_ => (default, "")
		};

		// The validator checks the usage that the kind of validation gives, so the testcase may ask for that one alone.
		if (purpose.Length is 0 || testcase.ExtendedKeyUsage is not ([] or [_]) || testcase.ExtendedKeyUsage is [var only] && only != purpose)
		{
			return new Outcome(Skipped, $"The validation kind {testcase.ValidationKind} with the extended key usages [{string.Join(", ", testcase.ExtendedKeyUsage)}] is not supported.");
		}

		Certificate peer;
		Certificate[] trusted;
		Certificate[] intermediates;

		try
		{
			peer = Certificate.DecodePem(testcase.PeerCertificate);
			trusted = [.. testcase.TrustedCerts.Select(static pem => Certificate.DecodePem(pem))];
			intermediates = [.. testcase.UntrustedIntermediates.Select(static pem => Certificate.DecodePem(pem))];
		}
		catch (ArgumentException e)
		{
			return new Outcome(Failure, $"A certificate does not decode: {e.InnerException?.Message ?? e.Message}");
		}

		using TrustAnchorCertificateValidator validator = new(trusted, importPublicKey) { MaxPathLength = testcase.MaxChainDepth ?? 8 };
		CertificateValidationContext context = new([peer, .. intermediates], usage)
		{
			HostName = usage is CertificateUsage.ServerAuthentication ? testcase.ExpectedPeerName?.Value : null,
			TimeProvider = new FixedTimeProvider(testcase.ValidationTime ?? DateTimeOffset.UtcNow)
		};

		CertificateValidationResult result = await validator.ValidateAsync(context);

		if (!result.IsValid)
		{
			return new Outcome(Failure, $"[{string.Join(", ", result.Errors)}] {result.PathEnd} after {result.Path.Count}: {result.Message}");
		}

		// The caller checks the key usage of the peer's certificate.
		X509KeyUsageFlags required = testcase.KeyUsage.Aggregate(X509KeyUsageFlags.None, static (flags, name) => flags | KeyUsageOf(name));

		if (peer.KeyUsage is { } keyUsage && (keyUsage & required) != required)
		{
			return new Outcome(Failure, $"The key usage {keyUsage} lacks {required}.");
		}

		return new Outcome(Success, $"{result.Path.Count} certificates");
	}

	private static X509KeyUsageFlags KeyUsageOf(string name)
	{
		return name switch
		{
			"digitalSignature" => X509KeyUsageFlags.DigitalSignature,
			"contentCommitment" => X509KeyUsageFlags.NonRepudiation,
			"keyEncipherment" => X509KeyUsageFlags.KeyEncipherment,
			"dataEncipherment" => X509KeyUsageFlags.DataEncipherment,
			"keyAgreement" => X509KeyUsageFlags.KeyAgreement,
			"keyCertSign" => X509KeyUsageFlags.KeyCertSign,
			"cRLSign" => X509KeyUsageFlags.CrlSign,
			"encipherOnly" => X509KeyUsageFlags.EncipherOnly,
			"decipherOnly" => X509KeyUsageFlags.DecipherOnly,
			_ => throw new ArgumentOutOfRangeException(nameof(name), name, "The key usage is not defined.")
		};
	}

	private sealed record Outcome(string Result, string Detail);
}
