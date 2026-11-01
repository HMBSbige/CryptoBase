using CryptoBase.Hashes;
using CryptoBase.Hashes.Sha2;
using CryptoBase.X509;
using System.Globalization;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using static CryptoBase.Tests.X509.X509TestUtils;

namespace CryptoBase.Tests.X509;

public class FingerprintCertificateValidatorTest
{
	private static readonly HashAlgorithmName Sha224 = new("SHA224");
	private static readonly HashAlgorithmName Md2 = new("MD2");

	[Test]
	public async Task AcceptsACertificateThatMatchesOneOfTheFingerprints()
	{
		Certificate certificate = SelfSignedP256();
		Certificate other = SelfSignedP256();

		CertificateValidationResult result = await Validate([Fingerprint(other, HashAlgorithmName.SHA256), Fingerprint(certificate, HashAlgorithmName.SHA256)], certificate);

		using (Assert.Multiple())
		{
			await Assert.That(result.IsValid).IsTrue().Because($"{result.Error} {result.Message}");
			await Assert.That(result.Path).Count().IsEqualTo(1);
			await Assert.That(result.Path[0]).IsSameReferenceAs(certificate);
			await Assert.That(result.PathEnd).IsEqualTo(CertificatePathEnd.TrustAnchor);
		}
	}

	// RFC 8122, Sec. 5.1: the fingerprints of the most preferred hash function alone decide, so a weaker one that matches does not stand in for a stronger one that does not.
	[Test]
	public async Task UsesOnlyTheMostPreferredHashFunction()
	{
		Certificate certificate = SelfSignedP256();
		Certificate other = SelfSignedP256();

		using (Assert.Multiple())
		{
			await AssertRejected(await Validate([Fingerprint(certificate, HashAlgorithmName.SHA1), Fingerprint(other, HashAlgorithmName.SHA256)], certificate), CertificateValidationError.UntrustedRoot);
			await AssertRejected(await Validate([Fingerprint(certificate, HashAlgorithmName.SHA256), Fingerprint(other, HashAlgorithmName.SHA384)], certificate), CertificateValidationError.UntrustedRoot);
			await AssertRejected(await Validate([Fingerprint(certificate, HashAlgorithmName.SHA384), Fingerprint(other, HashAlgorithmName.SHA512)], certificate), CertificateValidationError.UntrustedRoot);
			await Assert.That((await Validate([Fingerprint(certificate, HashAlgorithmName.SHA512), Fingerprint(other, HashAlgorithmName.SHA256)], certificate)).IsValid).IsTrue();
			await Assert.That((await Validate([Fingerprint(certificate, HashAlgorithmName.SHA1)], certificate)).IsValid).IsTrue();
		}
	}

	// RFC 8122, Sec. 5 forbids verifying with MD5 and MD2; SHA-224 is not available.
	[Test]
	public async Task IgnoresTheHashFunctionsThatItDoesNotUse()
	{
		Certificate certificate = SelfSignedP256();
		Certificate other = SelfSignedP256();
		byte[] sha224 = new byte[28];
		HashAlgorithm<Sha224Core>.HashData(certificate.Encoded.Span, sha224);
		CertificateFingerprint md5 = Fingerprint(certificate, HashAlgorithmName.MD5);

		using (Assert.Multiple())
		{
			await AssertRejected(await Validate([md5, Fingerprint(other, HashAlgorithmName.SHA1)], certificate), CertificateValidationError.UntrustedRoot);
			await AssertRejected(await Validate([md5], certificate), CertificateValidationError.UnsupportedAlgorithm);
			await AssertRejected(await Validate([new CertificateFingerprint(Md2, new byte[16])], certificate), CertificateValidationError.UnsupportedAlgorithm);
			await AssertRejected(await Validate([new CertificateFingerprint(Sha224, sha224)], certificate), CertificateValidationError.UnsupportedAlgorithm);
			await AssertRejected(await Validate([new CertificateFingerprint(HashAlgorithmName.SHA3_256, new byte[32])], certificate), CertificateValidationError.UnsupportedAlgorithm);
		}
	}

	// The digest of the first certificate alone counts: not its validity period, its usage, the host name or the other certificates.
	[Test]
	public async Task ComparesOnlyTheDigestOfThePeersCertificate()
	{
		using ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
		CertificateRequest request = new("CN=Expired", key, HashAlgorithmName.SHA256);
		request.CertificateExtensions.Add(EnhancedKeyUsage(ClientAuthenticationOid));
		using X509Certificate2 expired = request.CreateSelfSigned(Now.AddDays(-10), Now.AddDays(-5));
		Certificate certificate = Certificate.Decode(expired.RawData);
		Certificate other = SelfSignedP256();
		FingerprintCertificateValidator validator = new([Fingerprint(certificate, HashAlgorithmName.SHA256)]);

		CertificateValidationResult accepted = await validator.ValidateAsync(new CertificateValidationContext([certificate, other], CertificateUsage.ServerAuthentication) { HostName = "unrelated.example" });
		CertificateValidationResult second = await validator.ValidateAsync(new CertificateValidationContext([other, certificate], CertificateUsage.ClientAuthentication));

		using (Assert.Multiple())
		{
			await Assert.That(accepted.IsValid).IsTrue().Because($"{accepted.Error} {accepted.Message}");
			await AssertRejected(second, CertificateValidationError.UntrustedRoot);
		}
	}

	[Test]
	public async Task ChecksItsArgumentsAndHonorsCancellation()
	{
		Certificate certificate = SelfSignedP256();
		FingerprintCertificateValidator validator = new([Fingerprint(certificate, HashAlgorithmName.SHA256)]);
		using CancellationTokenSource canceled = new();
		await canceled.CancelAsync();
		CancellationToken token = canceled.Token;

		using (Assert.Multiple())
		{
			await Assert.That(() => new FingerprintCertificateValidator(null!)).ThrowsExactly<ArgumentNullException>();
			await Assert.That(() => new FingerprintCertificateValidator([])).ThrowsExactly<ArgumentException>().WithParameterName("fingerprints");
			await Assert.That(() => new FingerprintCertificateValidator([null!])).ThrowsExactly<ArgumentException>().WithParameterName("fingerprints");
			await Assert.That(async () => await validator.ValidateAsync(null!)).ThrowsExactly<ArgumentNullException>();
			await Assert.That(async () => await validator.ValidateAsync(new CertificateValidationContext([certificate], CertificateUsage.ServerAuthentication), token)).Throws<OperationCanceledException>();
		}
	}

	// The example of RFC 8842, Sec. 7, from RFC 8122, Sec. 3.4.
	[Test]
	[Arguments("SHA-256 12:DF:3E:5D:49:6B:19:E5:7C:AB:4A:AD:B9:B1:3F:82:18:3B:54:02:12:DF:3E:5D:49:6B:19:E5:7C:AB:4A:AD", "SHA256", "12DF3E5D496B19E57CAB4AADB9B13F82183B540212DF3E5D496B19E57CAB4AAD", "sha-256 12:DF:3E:5D:49:6B:19:E5:7C:AB:4A:AD:B9:B1:3F:82:18:3B:54:02:12:DF:3E:5D:49:6B:19:E5:7C:AB:4A:AD")]
	[Arguments("SHA-1 4A:AD:B9:B1:3F:82:18:3B:54:02:12:DF:3E:5D:49:6B:19:E5:7C:AB", "SHA1", "4AADB9B13F82183B540212DF3E5D496B19E57CAB", "sha-1 4A:AD:B9:B1:3F:82:18:3B:54:02:12:DF:3E:5D:49:6B:19:E5:7C:AB")]
	[Arguments("sha-384 00:01:02:03:04:05:06:07:08:09:0A:0B:0C:0D:0E:0F:10:11:12:13:14:15:16:17:18:19:1A:1B:1C:1D:1E:1F:20:21:22:23:24:25:26:27:28:29:2A:2B:2C:2D:2E:2F", "SHA384", "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F", null)]
	[Arguments("Md5 ab:cd:ef:01:23:45:67:89:ab:cd:ef:01:23:45:67:89", "MD5", "ABCDEF0123456789ABCDEF0123456789", "md5 AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89")]
	[Arguments("md2 00:01:02:03:04:05:06:07:08:09:0A:0B:0C:0D:0E:0F", "MD2", "000102030405060708090A0B0C0D0E0F", null)]
	[Arguments("sha-224 00:01:02:03:04:05:06:07:08:09:0A:0B:0C:0D:0E:0F:10:11:12:13:14:15:16:17:18:19:1A:1B", "SHA224", "000102030405060708090A0B0C0D0E0F101112131415161718191A1B", null)]
	[Arguments("sha3-256 01:02", "sha3-256", "0102", null)]
	[Arguments("SHA3-256 01", "SHA3-256", "01", null)]
	[Arguments("sha256 01:02", "sha256", "0102", null)]
	[Arguments("Sha1 4A:AD:B9:B1:3F:82:18:3B:54:02:12:DF:3E:5D:49:6B:19:E5:7C:AB", "Sha1", "4AADB9B13F82183B540212DF3E5D496B19E57CAB", null)]
	public async Task ParsesFingerprintAttributeValues(string value, string hashAlgorithm, string digest, string? formatted)
	{
		CertificateFingerprint fingerprint = CertificateFingerprint.Parse(value);

		using (Assert.Multiple())
		{
			await Assert.That(fingerprint.HashAlgorithm).IsEqualTo(new HashAlgorithmName(hashAlgorithm));
			await Assert.That(Convert.ToHexString(fingerprint.Digest.Span)).IsEqualTo(digest);
			await Assert.That(fingerprint.ToString()).IsEqualTo(formatted ?? value);
			await Assert.That(CertificateFingerprint.TryParse(value, out CertificateFingerprint? parsed)).IsTrue();
			await Assert.That(parsed!.ToString()).IsEqualTo(fingerprint.ToString());
		}
	}

	[Test]
	[Arguments("")]
	[Arguments("sha-256")]
	[Arguments("sha-256 ")]
	[Arguments(" sha-256 01")]
	[Arguments("sha-256  01")]
	[Arguments("sha-256 01:02")]
	[Arguments("sha-1 01:02:03:04:05:06:07:08:09:0A:0B:0C:0D:0E:0F:10:11:12:13:14:15")]
	[Arguments("sha3-256 1")]
	[Arguments("sha3-256 012")]
	[Arguments("sha3-256 01-02")]
	[Arguments("sha3-256 01:02:")]
	[Arguments("sha3-256 :01:02")]
	[Arguments("sha3-256 0G")]
	[Arguments("sha3-256 01\r\n")]
	[Arguments("sha/256 01")]
	[Arguments("sha\"256 01")]
	[Arguments("sha-256 01")]
	[Arguments("SHA1 4A:AD:B9:B1:3F:82:18:3B:54:02:12:DF:3E:5D:49:6B:19:E5:7C:AB")]
	[Arguments("SHA256 12:DF:3E:5D:49:6B:19:E5:7C:AB:4A:AD:B9:B1:3F:82:18:3B:54:02:12:DF:3E:5D:49:6B:19:E5:7C:AB:4A:AD")]
	[Arguments("SHA224 01")]
	[Arguments("SHA384 01")]
	[Arguments("SHA512 01")]
	[Arguments("\u017Fha-1 4A:AD:B9:B1:3F:82:18:3B:54:02:12:DF:3E:5D:49:6B:19:E5:7C:AB")]
	public async Task RejectsWhatIsNotAFingerprintAttributeValue(string value)
	{
		using (Assert.Multiple())
		{
			await Assert.That(CertificateFingerprint.TryParse(value, out CertificateFingerprint? fingerprint)).IsFalse();
			await Assert.That(fingerprint).IsNull();
			await Assert.That(() => CertificateFingerprint.Parse(value)).ThrowsExactly<FormatException>();
		}
	}

	[Test]
	public async Task FingerprintsCheckTheirValues()
	{
		byte[] digest = new byte[32];
		CertificateFingerprint fingerprint = new(HashAlgorithmName.SHA256, digest);
		digest[0] = 1;

		using (Assert.Multiple())
		{
			await Assert.That(fingerprint.Digest.Span[0]).IsEqualTo((byte)0);
			await Assert.That(() => new CertificateFingerprint(HashAlgorithmName.SHA256, new byte[31])).ThrowsExactly<ArgumentException>().WithParameterName("digest");
			await Assert.That(() => new CertificateFingerprint(HashAlgorithmName.SHA3_256, [])).ThrowsExactly<ArgumentException>().WithParameterName("digest");
			await Assert.That(() => new CertificateFingerprint(default, new byte[32])).ThrowsExactly<ArgumentException>().WithParameterName("hashAlgorithm");
			await Assert.That(() => new CertificateFingerprint(new HashAlgorithmName(""), new byte[32])).ThrowsExactly<ArgumentException>().WithParameterName("hashAlgorithm");
			await Assert.That(() => new CertificateFingerprint(new HashAlgorithmName("SHA 256"), new byte[32])).ThrowsExactly<ArgumentException>().WithParameterName("hashAlgorithm");

			// A registered name in either case or the HashAlgorithmName of .NET is the registered hash function, with its digest length.
			await Assert.That(() => new CertificateFingerprint(new HashAlgorithmName("SHA-256"), new byte[1])).ThrowsExactly<ArgumentException>().WithParameterName("digest");
			await Assert.That(() => new CertificateFingerprint(new HashAlgorithmName("SHA1"), new byte[1])).ThrowsExactly<ArgumentException>().WithParameterName("digest");
			await Assert.That(new CertificateFingerprint(new HashAlgorithmName("SHA-256"), digest).HashAlgorithm).IsEqualTo(HashAlgorithmName.SHA256);
			await Assert.That(new CertificateFingerprint(new HashAlgorithmName("Md5"), new byte[16]).HashAlgorithm).IsEqualTo(HashAlgorithmName.MD5);

			// Any other token is kept as it is.
			CertificateFingerprint unregistered = new(new HashAlgorithmName("sha256"), [1]);
			await Assert.That(unregistered.HashAlgorithm).IsNotEqualTo(HashAlgorithmName.SHA256);
			await Assert.That(unregistered.ToString()).IsEqualTo("sha256 01");
		}
	}

	// A fingerprint names its hash function in any of the forms of the constructor, and with SHA-256 the validator uses it as the attribute value "sha-256" would be; an unregistered token whose letters spell another name is not that hash function.
	[Test]
	public async Task NamesOfTheSameHashFunctionValidateAlike()
	{
		Certificate certificate = SelfSignedP256();
		byte[] sha256 = SHA256.HashData(certificate.Encoded.Span);
		byte[] sha1 = SHA1.HashData(certificate.Encoded.Span);
		string hex = string.Join(':', sha256.Select(static value => value.ToString("X2", CultureInfo.InvariantCulture)));

		using (Assert.Multiple())
		{
			foreach (CertificateFingerprint fingerprint in (CertificateFingerprint[])[new(HashAlgorithmName.SHA256, sha256), new(new HashAlgorithmName("SHA-256"), sha256), new(new HashAlgorithmName("sha-256"), sha256), CertificateFingerprint.Parse($"SHA-256 {hex}")])
			{
				await Assert.That((await Validate([fingerprint], certificate)).IsValid).IsTrue().Because(fingerprint.ToString());
				await Assert.That(fingerprint.ToString()).IsEqualTo($"sha-256 {hex}");
			}

			await AssertRejected(await Validate([CertificateFingerprint.Parse($"sha256 {hex}")], certificate), CertificateValidationError.UnsupportedAlgorithm);
			await AssertRejected(await Validate([new CertificateFingerprint(new HashAlgorithmName("sha1"), sha1)], certificate), CertificateValidationError.UnsupportedAlgorithm);
		}
	}

	// For random names and digests: the constructor accepts what the rules allow, Parse what they allow in an attribute value, and the result of either round-trips through ToString, Parse and the constructor.
	[Test]
	public async Task ConstructionParsingAndFormattingAgree()
	{
		Random random = new(8122);
		List<string> failures = [];

		for (int i = 0; i < 20_000; ++i)
		{
			string name = RandomName(random);
			int registered = Array.FindIndex(RegisteredHashFunctions, function => Ascii.EqualsIgnoreCase(function.Name, name));
			int algorithm = Array.FindIndex(RegisteredHashFunctions, function => function.Algorithm == name);
			int function = registered >= 0 ? registered : algorithm;
			byte[] digest = RandomNumberGenerator.GetBytes(function >= 0 && random.Next(2) is 0 ? RegisteredHashFunctions[function].Length : random.Next(0, 70));
			bool token = name.Length > 0 && name.All(static c => c is '\x21' or >= '\x23' and <= '\x27' or '\x2A' or '\x2B' or '\x2D' or '\x2E' or >= '\x30' and <= '\x39' or >= '\x41' and <= '\x5A' or >= '\x5E' and <= '\x7E');
			string text = $"{name} {string.Join(':', digest.Select(value => value.ToString(random.Next(2) is 0 ? "X2" : "x2", CultureInfo.InvariantCulture)))}";
			bool constructs = token && (function >= 0 ? digest.Length == RegisteredHashFunctions[function].Length : digest.Length > 0);
			bool parses = token && (registered >= 0 ? digest.Length == RegisteredHashFunctions[registered].Length : algorithm < 0 && digest.Length > 0);
			string expectedName = function >= 0 ? RegisteredHashFunctions[function].Algorithm : name;
			CertificateFingerprint? constructed;

			try
			{
				constructed = new CertificateFingerprint(new HashAlgorithmName(name), digest);
			}
			catch (ArgumentException)
			{
				constructed = null;
			}

			bool parsed = CertificateFingerprint.TryParse(text, out CertificateFingerprint? fromText);

			if (constructed is not null != constructs || parsed != parses)
			{
				failures.Add($"{text}: constructs {constructed is not null}, parses {parsed}");
				continue;
			}

			foreach (CertificateFingerprint? fingerprint in (CertificateFingerprint?[])[constructed, fromText])
			{
				if (fingerprint is null)
				{
					continue;
				}

				string formatted = fingerprint.ToString();

				if (fingerprint.HashAlgorithm.Name != expectedName || !fingerprint.Digest.Span.SequenceEqual(digest)
					|| !CertificateFingerprint.TryParse(formatted, out CertificateFingerprint? reparsed) || !Same(reparsed, fingerprint)
					|| !Same(new CertificateFingerprint(fingerprint.HashAlgorithm, fingerprint.Digest.Span), fingerprint))
				{
					failures.Add($"{text}: {formatted} does not round-trip");
				}
			}
		}

		await Assert.That(failures).IsEmpty();

		static bool Same(CertificateFingerprint first, CertificateFingerprint second)
		{
			return first.HashAlgorithm == second.HashAlgorithm && first.Digest.Span.SequenceEqual(second.Digest.Span) && first.ToString() == second.ToString();
		}
	}

	// Registered names in random case, the HashAlgorithmName of each registered hash function in random case, random tokens, and names with a character that a token does not allow, such as one that case folding takes for an ASCII letter.
	private static string RandomName(Random random)
	{
		const string tokenCharacters = "!#$%&'*+-.0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ^_`abcdefghijklmnopqrstuvwxyz{|}~";
		const string otherCharacters = " \"(),/:;<=>?@[\\]\x7F\u00E9\u017F\u212A";

		switch (random.Next(5))
		{
			case 0:
				return RandomCase(RegisteredHashFunctions[random.Next(RegisteredHashFunctions.Length)].Name, random);
			case 1:
				string algorithm = RegisteredHashFunctions[random.Next(RegisteredHashFunctions.Length)].Algorithm;
				return random.Next(2) is 0 ? algorithm : RandomCase(algorithm, random);
			case 2 or 3:
				return string.Concat(Enumerable.Range(0, random.Next(1, 12)).Select(_ => tokenCharacters[random.Next(tokenCharacters.Length)]));
			default:
				string name = string.Concat(Enumerable.Range(0, random.Next(0, 8)).Select(_ => tokenCharacters[random.Next(tokenCharacters.Length)]));
				return random.Next(4) is 0 ? name : name.Insert(random.Next(name.Length + 1), otherCharacters[random.Next(otherCharacters.Length)].ToString());
		}

		static string RandomCase(string value, Random random)
		{
			return string.Concat(value.Select(c => random.Next(2) is 0 ? char.ToUpperInvariant(c) : char.ToLowerInvariant(c)));
		}
	}

	private static CertificateFingerprint Fingerprint(Certificate certificate, HashAlgorithmName hashAlgorithm)
	{
		return new CertificateFingerprint(hashAlgorithm, CryptographicOperations.HashData(hashAlgorithm, certificate.Encoded.Span));
	}

	// RFC 8122, Sec. 5, as an oracle independent of the implementation: the registered names, the HashAlgorithmName of each registered hash function, which the constructor alone takes for it, and the digest length of each.
	private static readonly (string Name, string Algorithm, int Length)[] RegisteredHashFunctions = [("sha-1", "SHA1", 20), ("sha-224", "SHA224", 28), ("sha-256", "SHA256", 32), ("sha-384", "SHA384", 48), ("sha-512", "SHA512", 64), ("md5", "MD5", 16), ("md2", "MD2", 16)];

	private static ValueTask<CertificateValidationResult> Validate(CertificateFingerprint[] fingerprints, Certificate certificate)
	{
		return new FingerprintCertificateValidator(fingerprints).ValidateAsync(new CertificateValidationContext([certificate], CertificateUsage.ServerAuthentication));
	}

	private static async Task AssertRejected(CertificateValidationResult result, CertificateValidationError error)
	{
		await Assert.That(result.IsValid).IsFalse();
		await Assert.That(result.Errors).IsEquivalentTo([error], CollectionOrdering.Matching).Because(result.Message ?? "");
		await Assert.That(result.PathEnd).IsEqualTo(CertificatePathEnd.None);
	}
}
