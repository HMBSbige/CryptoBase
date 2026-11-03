using CryptoBase.Abstractions.Signatures;
using CryptoBase.Signatures;
using CryptoBase.Signatures.Rsa;
using static CryptoBase.Tests.Signatures.Rsa.RsaTestUtils;
using static CryptoBase.Tests.Signatures.SignatureTestUtils;

namespace CryptoBase.Tests.Wycheproof;

public class WycheproofRsaTest
{
	// The RSASSA-PKCS1-v1_5 verification files whose hash has no SignatureAlgorithm.
	private static readonly string[] OtherHashFiles =
	[
		"rsa_signature_2048_sha224_test.json", "rsa_signature_2048_sha3_224_test.json", "rsa_signature_2048_sha3_256_test.json", "rsa_signature_2048_sha3_384_test.json",
		"rsa_signature_2048_sha3_512_test.json", "rsa_signature_2048_sha512_224_test.json", "rsa_signature_2048_sha512_256_test.json", "rsa_signature_3072_sha3_256_test.json",
		"rsa_signature_3072_sha3_384_test.json", "rsa_signature_3072_sha3_512_test.json", "rsa_signature_3072_sha512_256_test.json", "rsa_signature_4096_sha512_256_test.json"
	];

	// Every RSASSA-PSS file: those of SHA-256, SHA-384 and SHA-512 with MGF1 of the same hash and a salt as long as it, with and without parameters, and those of other hashes, salt lengths and
	// MGF1 hashes, whose keys must not import or must not verify them.
	private static readonly string[] PssFiles =
	[
		"rsa_pss_2048_sha1_mgf1_20_params_test.json", "rsa_pss_2048_sha1_mgf1_20_test.json", "rsa_pss_2048_sha256_mgf1_0_params_test.json", "rsa_pss_2048_sha256_mgf1_0_test.json",
		"rsa_pss_2048_sha256_mgf1_32_params_test.json", "rsa_pss_2048_sha256_mgf1_32_test.json", "rsa_pss_2048_sha256_mgf1sha1_20_test.json", "rsa_pss_2048_sha384_mgf1_48_test.json",
		"rsa_pss_2048_sha512_224_mgf1_28_test.json", "rsa_pss_2048_sha512_256_mgf1_32_test.json", "rsa_pss_2048_sha512_mgf1sha256_32_params_test.json", "rsa_pss_2048_shake128_test.json",
		"rsa_pss_2048_shake256_test.json", "rsa_pss_3072_sha256_mgf1_32_params_test.json", "rsa_pss_3072_sha256_mgf1_32_test.json", "rsa_pss_3072_shake128_test.json",
		"rsa_pss_3072_shake256_test.json", "rsa_pss_4096_sha256_mgf1_32_test.json", "rsa_pss_4096_sha384_mgf1_48_test.json", "rsa_pss_4096_sha512_mgf1_32_params_test.json",
		"rsa_pss_4096_sha512_mgf1_32_test.json", "rsa_pss_4096_sha512_mgf1_64_params_test.json", "rsa_pss_4096_sha512_mgf1_64_test.json", "rsa_pss_4096_shake256_test.json",
		"rsa_pss_misc_params_test.json", "rsa_pss_misc_test.json"
	];

	// The acceptable vectors that the tests accept carry these flags in each file: small moduli, small public exponents and SHA-1 in the signature generation files, and a DigestInfo without the NULL
	// parameters in the verification files (RFC 5246, Sec. 4.7). A file with any other set fails, so that its vectors are decided anew.
	private static readonly Dictionary<string, string[]> AcceptableFlags = new()
	{
		["rsa_pkcs1_1024_sig_gen_test.json"] = ["SmallModulus", "WeakHash", "SmallPublicKey"],
		["rsa_pkcs1_1536_sig_gen_test.json"] = ["SmallModulus"],
		["rsa_pkcs1_2048_sig_gen_test.json"] = ["WeakHash", "SmallPublicKey"],
		["rsa_pkcs1_3072_sig_gen_test.json"] = ["SmallPublicKey"],
		["rsa_pkcs1_4096_sig_gen_test.json"] = [],
		["rsa_signature_2048_sha256_test.json"] = ["MissingNull"],
		["rsa_signature_2048_sha384_test.json"] = ["MissingNull"],
		["rsa_signature_2048_sha512_test.json"] = ["MissingNull"],
		["rsa_signature_3072_sha256_test.json"] = ["MissingNull"],
		["rsa_signature_3072_sha384_test.json"] = ["MissingNull"],
		["rsa_signature_3072_sha512_test.json"] = ["MissingNull"],
		["rsa_signature_4096_sha256_test.json"] = ["MissingNull"],
		["rsa_signature_4096_sha384_test.json"] = ["MissingNull"],
		["rsa_signature_4096_sha512_test.json"] = ["MissingNull"],
		["rsa_signature_8192_sha256_test.json"] = ["MissingNull"],
		["rsa_signature_8192_sha384_test.json"] = ["MissingNull"],
		["rsa_signature_8192_sha512_test.json"] = ["MissingNull"],
	};

	public static IEnumerable<Func<string>> AcceptableFlagFiles()
	{
		return AcceptableFlags.Keys.Select(static fileName => (Func<string>)(() => fileName));
	}

	public static IEnumerable<Func<string>> OtherHashFileNames()
	{
		return OtherHashFiles.Select(static fileName => (Func<string>)(() => fileName));
	}

	public static IEnumerable<Func<RsaSignatureTestVector>> PssVectors()
	{
		return PssFiles.SelectMany(static fileName => WycheproofVectors.Load<RsaVerifyTestGroup, RsaSignatureTestVector>(fileName)).Select(static vector => (Func<RsaSignatureTestVector>)(() => vector));
	}

	[Test]
	[MethodDataSource(nameof(AcceptableFlagFiles))]
	public async Task AcceptableFlagsArePinned(string fileName)
	{
		IEnumerable<RsaSignatureTestVector> vectors = fileName.Contains("sig_gen", StringComparison.Ordinal) ? WycheproofVectors.Load<RsaSignTestGroup, RsaSignatureTestVector>(fileName) : WycheproofVectors.Load<RsaVerifyTestGroup, RsaSignatureTestVector>(fileName);

		await Assert.That(vectors.Where(static vector => vector.Result is WycheproofResult.Acceptable).SelectMany(static vector => vector.Flags).Distinct()).IsEquivalentTo(AcceptableFlags[fileName]);
	}

	// Signing with the group's key gives the file's signature byte for byte, which verifies, and the key's encodings, the RSA PRIVATE KEY block included, give the same key. SHA-1 and SHA-224 have no
	// SignatureAlgorithm, so their signatures verify with none.
	[Test]
	[WycheproofVectors<RsaSignTestGroup, RsaSignatureTestVector>("rsa_pkcs1_1024_sig_gen_test.json")]
	[WycheproofVectors<RsaSignTestGroup, RsaSignatureTestVector>("rsa_pkcs1_1536_sig_gen_test.json")]
	[WycheproofVectors<RsaSignTestGroup, RsaSignatureTestVector>("rsa_pkcs1_2048_sig_gen_test.json")]
	[WycheproofVectors<RsaSignTestGroup, RsaSignatureTestVector>("rsa_pkcs1_3072_sig_gen_test.json")]
	[WycheproofVectors<RsaSignTestGroup, RsaSignatureTestVector>("rsa_pkcs1_4096_sig_gen_test.json")]
	public async Task Pkcs1SignatureGeneration(RsaSignatureTestVector vector)
	{
		byte[] pkcs8 = vector.PrivateKeyPkcs8 ?? throw new InvalidOperationException("The group has no private key.");
		using RsaKey key = RsaKey.ImportPkcs8PrivateKey(pkcs8);
		using RsaKey publicKey = RsaKey.ImportSubjectPublicKeyInfo(vector.PublicKeyDer);
		using ISignatureKey fromPem = SignatureKey.ImportFromPem(vector.PrivateKeyPem ?? throw new InvalidOperationException("The group has no RSA PRIVATE KEY block."));

		using (Assert.Multiple())
		{
			await Assert.That(vector.Result).IsNotEqualTo(WycheproofResult.Invalid);
			await Assert.That(ExportPkcs8PrivateKey(key)).IsEquivalentTo(pkcs8, CollectionOrdering.Matching);
			await Assert.That(ExportPkcs8PrivateKey(fromPem)).IsEquivalentTo(pkcs8, CollectionOrdering.Matching);
			await Assert.That(ExportSubjectPublicKeyInfo(key)).IsEquivalentTo(vector.PublicKeyDer, CollectionOrdering.Matching);
			await Assert.That(ExportRsaPublicKey(key)).IsEquivalentTo(vector.PublicKeyAsn, CollectionOrdering.Matching);

			if (Pkcs1AlgorithmOf(vector.Sha) is { } algorithm)
			{
				await Assert.That(Sign(key, algorithm, vector.Msg)).IsEquivalentTo(vector.Sig, CollectionOrdering.Matching);
				await Assert.That(Sign(fromPem, algorithm, vector.Msg)).IsEquivalentTo(vector.Sig, CollectionOrdering.Matching);
				await Assert.That(publicKey.Verify(algorithm, vector.Msg, vector.Sig)).IsTrue();
			}
			else
			{
				foreach (SignatureAlgorithm other in Algorithms.Where(publicKey.Supports))
				{
					await Assert.That(publicKey.Verify(other, vector.Msg, vector.Sig)).IsFalse().Because(other.ToString());
				}
			}
		}
	}

	// The acceptable vectors, whose DigestInfo lacks the NULL parameters, verify. No vector verifies with another algorithm, but those that the file made with another hash or with RSASSA-PSS, which
	// may be valid signatures of that algorithm.
	[Test]
	[WycheproofVectors<RsaVerifyTestGroup, RsaSignatureTestVector>("rsa_signature_2048_sha256_test.json")]
	[WycheproofVectors<RsaVerifyTestGroup, RsaSignatureTestVector>("rsa_signature_2048_sha384_test.json")]
	[WycheproofVectors<RsaVerifyTestGroup, RsaSignatureTestVector>("rsa_signature_2048_sha512_test.json")]
	[WycheproofVectors<RsaVerifyTestGroup, RsaSignatureTestVector>("rsa_signature_3072_sha256_test.json")]
	[WycheproofVectors<RsaVerifyTestGroup, RsaSignatureTestVector>("rsa_signature_3072_sha384_test.json")]
	[WycheproofVectors<RsaVerifyTestGroup, RsaSignatureTestVector>("rsa_signature_3072_sha512_test.json")]
	[WycheproofVectors<RsaVerifyTestGroup, RsaSignatureTestVector>("rsa_signature_4096_sha256_test.json")]
	[WycheproofVectors<RsaVerifyTestGroup, RsaSignatureTestVector>("rsa_signature_4096_sha384_test.json")]
	[WycheproofVectors<RsaVerifyTestGroup, RsaSignatureTestVector>("rsa_signature_4096_sha512_test.json")]
	[WycheproofVectors<RsaVerifyTestGroup, RsaSignatureTestVector>("rsa_signature_8192_sha256_test.json")]
	[WycheproofVectors<RsaVerifyTestGroup, RsaSignatureTestVector>("rsa_signature_8192_sha384_test.json")]
	[WycheproofVectors<RsaVerifyTestGroup, RsaSignatureTestVector>("rsa_signature_8192_sha512_test.json")]
	public async Task Pkcs1Verification(RsaSignatureTestVector vector)
	{
		SignatureAlgorithm algorithm = Pkcs1AlgorithmOf(vector.Sha) ?? throw new InvalidOperationException($"{vector.Sha} has no SignatureAlgorithm.");
		using RsaKey key = RsaKey.ImportSubjectPublicKeyInfo(vector.PublicKeyDer);

		using (Assert.Multiple())
		{
			await Assert.That(Algorithms.Where(key.Supports)).IsEquivalentTo(Algorithms, CollectionOrdering.Matching);
			await Assert.That(ExportSubjectPublicKeyInfo(key)).IsEquivalentTo(vector.PublicKeyDer, CollectionOrdering.Matching);
			await Assert.That(key.Verify(algorithm, vector.Msg, vector.Sig)).IsEqualTo(vector.Result is not WycheproofResult.Invalid);

			if (!IsOfAnotherAlgorithm(vector))
			{
				foreach (SignatureAlgorithm other in Algorithms.Where(other => other != algorithm))
				{
					await Assert.That(key.Verify(other, vector.Msg, vector.Sig)).IsFalse().Because(other.ToString());
				}
			}
		}
	}

	// The keys import, and no vector, valid or not, verifies with any of the algorithms, but those that the file made with another hash or with RSASSA-PSS.
	[Test]
	[MethodDataSource(nameof(OtherHashFileNames))]
	public async Task Pkcs1VectorsOfOtherHashesVerifyWithNoAlgorithm(string fileName)
	{
		List<string> accepted = [];
		int count = 0;

		foreach (RsaSignatureTestVector vector in WycheproofVectors.Load<RsaVerifyTestGroup, RsaSignatureTestVector>(fileName).Where(static vector => !IsOfAnotherAlgorithm(vector)))
		{
			using RsaKey key = RsaKey.ImportSubjectPublicKeyInfo(vector.PublicKeyDer);
			accepted.AddRange(Algorithms.Where(algorithm => key.Verify(algorithm, vector.Msg, vector.Sig)).Select(algorithm => $"{vector}, {algorithm}"));
			++count;
		}

		using (Assert.Multiple())
		{
			await Assert.That(count).IsGreaterThan(0);
			await Assert.That(accepted).IsEmpty();
		}
	}

	// A vector verifies only with the SignatureAlgorithm of its hash, if MGF1 has the same hash and the salt is as long as the hash; in a group with another salt length, only the invalid vector that the
	// file made with a salt as long as the hash does. A key with RSASSA-PSS parameters supports the one algorithm that they allow (RFC 4055, Sec. 3.3), and one whose parameters allow none does not
	// import; other keys support every algorithm.
	[Test]
	[MethodDataSource(nameof(PssVectors))]
	public async Task PssVerification(RsaSignatureTestVector vector)
	{
		bool withParameters = vector.GroupType is "RsassaPssWithParametersVerify";
		(SignatureAlgorithm algorithm, int hashLength) = PssAlgorithmOf(vector.Sha);
		bool sameHashes = vector.MgfSha == vector.Sha;
		int saltLength = vector.SaltLength ?? throw new InvalidOperationException("The group has no salt length.");

		await Assert.That(vector.Result).IsNotEqualTo(WycheproofResult.Acceptable);

		if (withParameters && !(algorithm is not default(SignatureAlgorithm) && sameHashes && saltLength <= hashLength))
		{
			await Assert.That(() => RsaKey.ImportSubjectPublicKeyInfo(vector.PublicKeyDer)).ThrowsExactly<NotSupportedException>();
			await Assert.That(() => SignatureKey.ImportSubjectPublicKeyInfo(vector.PublicKeyDer)).ThrowsExactly<NotSupportedException>();
			return;
		}

		using RsaKey key = RsaKey.ImportSubjectPublicKeyInfo(vector.PublicKeyDer);

		using (Assert.Multiple())
		{
			await Assert.That(Algorithms.Where(key.Supports)).IsEquivalentTo(withParameters ? [algorithm] : Algorithms, CollectionOrdering.Matching);
			await Assert.That(ExportSubjectPublicKeyInfo(key)).IsEquivalentTo(vector.PublicKeyDer, CollectionOrdering.Matching);

			if (algorithm is default(SignatureAlgorithm))
			{
				foreach (SignatureAlgorithm other in PssAlgorithms)
				{
					await Assert.That(key.Verify(other, vector.Msg, vector.Sig)).IsFalse().Because(other.ToString());
				}
			}
			else
			{
				bool expected = sameHashes && (saltLength == hashLength ? vector.Result is WycheproofResult.Valid : vector.Comment == $"s_len changed to {hashLength}");
				await Assert.That(key.Verify(algorithm, vector.Msg, vector.Sig)).IsEqualTo(expected);
			}
		}
	}

	// A vector that the file made with another hash or with RSASSA-PSS rather than RSASSA-PKCS1-v1_5.
	private static bool IsOfAnotherAlgorithm(RsaSignatureTestVector vector)
	{
		return vector.Flags.Any(static flag => flag is "WrongHash" or "WrongPrimitive");
	}

	private static SignatureAlgorithm? Pkcs1AlgorithmOf(string sha)
	{
		return sha switch
		{
			"SHA-256" => SignatureAlgorithm.RsaPkcs1Sha256,
			"SHA-384" => SignatureAlgorithm.RsaPkcs1Sha384,
			"SHA-512" => SignatureAlgorithm.RsaPkcs1Sha512,
			_ => null
		};
	}

	// The RSASSA-PSS algorithm of a hash and the hash's length, or default for a hash without one.
	private static (SignatureAlgorithm Algorithm, int HashLength) PssAlgorithmOf(string sha)
	{
		return sha switch
		{
			"SHA-256" => (SignatureAlgorithm.RsaPssSha256, 32),
			"SHA-384" => (SignatureAlgorithm.RsaPssSha384, 48),
			"SHA-512" => (SignatureAlgorithm.RsaPssSha512, 64),
			_ => default
		};
	}
}
