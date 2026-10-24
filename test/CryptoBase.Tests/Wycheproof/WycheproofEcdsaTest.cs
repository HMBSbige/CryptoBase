using CryptoBase.Abstractions.Signatures;
using CryptoBase.Signatures.Ecdsa;
using CryptoBase.Tests.EllipticCurves;
using System.Diagnostics.CodeAnalysis;
using System.Formats.Asn1;
using System.Numerics;
using static CryptoBase.Tests.Signatures.Ecdsa.EcdsaTestUtils;
using static CryptoBase.Tests.Signatures.SignatureTestUtils;

namespace CryptoBase.Tests.Wycheproof;

public class WycheproofEcdsaTest
{
	private static readonly string[] KeyEncodingFlags =
	[
		"InvalidAsn", "UnnamedCurve", "CompressedPoint", "CompressedPublic", "UnusedParam", "ModifiedCofactor", "ModifiedCurveParameter",
		"ModifiedGenerator", "NoCofactor", "WrongOrder"
	];

	// Each file's acceptable SubjectPublicKeyInfo vectors carry these flags and are all rejected. A file with any other set fails, so that its vectors are decided anew.
	private static readonly Dictionary<string, string[]> AcceptableFlags = new()
	{
		["ecdh_secp256r1_test.json"] = KeyEncodingFlags,
		["ecdh_secp384r1_test.json"] = KeyEncodingFlags,
		["ecdh_secp521r1_test.json"] = KeyEncodingFlags,
	};

	private static readonly Dictionary<string, string[]> DerFiles = new()
	{
		["secp256r1"] = ["ecdsa_secp256r1_sha256_test.json", "ecdsa_secp256r1_sha512_test.json"],
		["secp384r1"] = ["ecdsa_secp384r1_sha256_test.json", "ecdsa_secp384r1_sha384_test.json", "ecdsa_secp384r1_sha512_test.json"],
		["secp521r1"] = ["ecdsa_secp521r1_sha512_test.json"],
	};

	public static IEnumerable<EcdsaVerifyTestVector> VerificationVectors(string fileName)
	{
		return WycheproofVectors.Load<EcdsaVerifyTestGroup, EcdsaVerifyTestVector>(fileName);
	}

	public static IEnumerable<EcdhTestVector> SubjectPublicKeyInfoVectors(string fileName)
	{
		return WycheproofVectors.Load<EcdhTestVector>(fileName);
	}

	[Test]
	[MethodDataSource(nameof(VerificationVectors), Arguments = ["ecdsa_secp256r1_sha256_test.json"])]
	[MethodDataSource(nameof(VerificationVectors), Arguments = ["ecdsa_secp256r1_sha512_test.json"])]
	public Task DerVerificationP256(EcdsaVerifyTestVector vector)
	{
		return VerifyVerification<EcdsaP256>(vector, EcdsaSignatureFormat.Der);
	}

	[Test]
	[MethodDataSource(nameof(VerificationVectors), Arguments = ["ecdsa_secp384r1_sha256_test.json"])]
	[MethodDataSource(nameof(VerificationVectors), Arguments = ["ecdsa_secp384r1_sha384_test.json"])]
	[MethodDataSource(nameof(VerificationVectors), Arguments = ["ecdsa_secp384r1_sha512_test.json"])]
	public Task DerVerificationP384(EcdsaVerifyTestVector vector)
	{
		return VerifyVerification<EcdsaP384>(vector, EcdsaSignatureFormat.Der);
	}

	[Test]
	[MethodDataSource(nameof(VerificationVectors), Arguments = ["ecdsa_secp521r1_sha512_test.json"])]
	public Task DerVerificationP521(EcdsaVerifyTestVector vector)
	{
		return VerifyVerification<EcdsaP521>(vector, EcdsaSignatureFormat.Der);
	}

	[Test]
	[MethodDataSource(nameof(VerificationVectors), Arguments = ["ecdsa_secp256r1_sha256_p1363_test.json"])]
	[MethodDataSource(nameof(VerificationVectors), Arguments = ["ecdsa_secp256r1_sha512_p1363_test.json"])]
	public Task ConcatenatedVerificationP256(EcdsaVerifyTestVector vector)
	{
		return VerifyVerification<EcdsaP256>(vector, EcdsaSignatureFormat.Concatenated);
	}

	[Test]
	[MethodDataSource(nameof(VerificationVectors), Arguments = ["ecdsa_secp384r1_sha384_p1363_test.json"])]
	[MethodDataSource(nameof(VerificationVectors), Arguments = ["ecdsa_secp384r1_sha512_p1363_test.json"])]
	public Task ConcatenatedVerificationP384(EcdsaVerifyTestVector vector)
	{
		return VerifyVerification<EcdsaP384>(vector, EcdsaSignatureFormat.Concatenated);
	}

	[Test]
	[MethodDataSource(nameof(VerificationVectors), Arguments = ["ecdsa_secp521r1_sha512_p1363_test.json"])]
	public Task ConcatenatedVerificationP521(EcdsaVerifyTestVector vector)
	{
		return VerifyVerification<EcdsaP521>(vector, EcdsaSignatureFormat.Concatenated);
	}

	[Test]
	[MethodDataSource(nameof(SubjectPublicKeyInfoVectors), Arguments = ["ecdh_secp256r1_test.json"])]
	public Task SubjectPublicKeyInfoP256(EcdhTestVector vector)
	{
		return VerifySubjectPublicKeyInfo<EcdsaP256>(vector);
	}

	[Test]
	[MethodDataSource(nameof(SubjectPublicKeyInfoVectors), Arguments = ["ecdh_secp384r1_test.json"])]
	public Task SubjectPublicKeyInfoP384(EcdhTestVector vector)
	{
		return VerifySubjectPublicKeyInfo<EcdsaP384>(vector);
	}

	[Test]
	[MethodDataSource(nameof(SubjectPublicKeyInfoVectors), Arguments = ["ecdh_secp521r1_test.json"])]
	public Task SubjectPublicKeyInfoP521(EcdhTestVector vector)
	{
		return VerifySubjectPublicKeyInfo<EcdsaP521>(vector);
	}

	[Test]
	[Arguments("ecdh_secp256r1_test.json")]
	[Arguments("ecdh_secp384r1_test.json")]
	[Arguments("ecdh_secp521r1_test.json")]
	public async Task AcceptableSubjectPublicKeyInfoFlagsArePinned(string fileName)
	{
		IEnumerable<string> flags = SubjectPublicKeyInfoVectors(fileName).Where(static vector => vector.Result is WycheproofResult.Acceptable).SelectMany(static vector => vector.Flags);

		await Assert.That(flags.Distinct()).IsEquivalentTo(AcceptableFlags[fileName]);
	}

	// The valid vectors with x(R) = r + n, which verification accepts only by comparing x(R) with r + n as well as with r.
	[Test]
	[Arguments("secp256r1")]
	[Arguments("secp384r1")]
	[Arguments("secp521r1")]
	public async Task VectorsWithXAboveTheOrderVerify(string curveName)
	{
		CurveCase curve = CurveCase.Named(curveName);
		EcReference reference = curve.Reference;
		BigInteger n = curve.Order;
		List<string> found = [];

		using (Assert.Multiple())
		{
			foreach (string fileName in DerFiles[curve.Name])
			{
				foreach (EcdsaVerifyTestVector vector in VerificationVectors(fileName).Where(static vector => vector.Result is WycheproofResult.Valid))
				{
					AsnReader signature = new AsnReader(vector.Sig, AsnEncodingRules.DER).ReadSequence();
					BigInteger r = signature.ReadInteger();
					BigInteger s = signature.ReadInteger();

					if (r + n >= reference.P)
					{
						continue;
					}

					SignatureAlgorithm algorithm = AlgorithmOf(vector);
					byte[] hash = Hash(algorithm, vector.Msg);
					BigInteger e = new BigInteger(hash, isUnsigned: true, isBigEndian: true) >> Math.Max(0, 8 * hash.Length - curve.ScalarBitLength);
					BigInteger w = BigInteger.ModPow(s, n - 2, n);
					int length = curve.FieldLength;
					CurvePoint q = new(new BigInteger(vector.PublicKey.AsSpan(1, length), isUnsigned: true, isBigEndian: true), new BigInteger(vector.PublicKey.AsSpan(1 + length), isUnsigned: true, isBigEndian: true));
					CurvePoint? point = reference.Add(reference.Multiply(reference.Generator, e * w % n), reference.Multiply(q, r * w % n));

					if (point is null || point.X != r + n)
					{
						continue;
					}

					bool verified = curveName switch
					{
						"secp256r1" => VerifyDer<EcdsaP256>(vector),
						"secp384r1" => VerifyDer<EcdsaP384>(vector),
						_ => VerifyDer<EcdsaP521>(vector)
					};

					found.Add($"{fileName}, {vector}");
					await Assert.That(verified).IsTrue().Because($"{fileName}, {vector}");
				}
			}

			await Assert.That(found).IsNotEmpty();
		}
	}

	// Every group key is valid, and the files have no acceptable vectors.
	[SuppressMessage("ReSharper", "AccessToDisposedClosure", Justification = "Assertions are awaited before the key is disposed.")]
	private static async Task VerifyVerification<T>(EcdsaVerifyTestVector vector, EcdsaSignatureFormat format) where T : class, IEcdsa<T>
	{
		SignatureAlgorithm algorithm = AlgorithmOf(vector);
		using T key = T.ImportSubjectPublicKeyInfo(vector.PublicKeyDer);
		using T fromPublicKey = T.ImportPublicKey(vector.PublicKey);
		bool valid = vector.Result is WycheproofResult.Valid;

		using (Assert.Multiple())
		{
			await Assert.That(vector.Result).IsNotEqualTo(WycheproofResult.Acceptable);
			await Assert.That(ExportPublicKey(key)).IsEquivalentTo(vector.PublicKey, CollectionOrdering.Matching);
			await Assert.That(key.Verify(algorithm, vector.Msg, vector.Sig, format)).IsEqualTo(valid);
			await Assert.That(fromPublicKey.Verify(algorithm, vector.Msg, vector.Sig, format)).IsEqualTo(valid);

			if (format is EcdsaSignatureFormat.Der)
			{
				await Assert.That(key.Verify(algorithm, vector.Msg, vector.Sig)).IsEqualTo(valid);
			}
		}
	}

	private static bool VerifyDer<T>(EcdsaVerifyTestVector vector) where T : class, IEcdsa<T>
	{
		using T key = T.ImportPublicKey(vector.PublicKey);
		return key.Verify(AlgorithmOf(vector), vector.Msg, vector.Sig);
	}

	private static SignatureAlgorithm AlgorithmOf(EcdsaVerifyTestVector vector)
	{
		return vector.Sha switch
		{
			"SHA-256" => SignatureAlgorithm.EcdsaSha256,
			"SHA-384" => SignatureAlgorithm.EcdsaSha384,
			"SHA-512" => SignatureAlgorithm.EcdsaSha512,
			_ => throw new NotSupportedException(vector.Sha)
		};
	}

	private static async Task VerifySubjectPublicKeyInfo<T>(EcdhTestVector vector) where T : class, IEcdsa<T>
	{
		if (vector.Result is WycheproofResult.Valid)
		{
			using T key = T.ImportSubjectPublicKeyInfo(vector.Public);
			await Assert.That(ExportSubjectPublicKeyInfo(key)).IsEquivalentTo(vector.Public, CollectionOrdering.Matching);
			return;
		}

		await Assert.That(() => T.ImportSubjectPublicKeyInfo(vector.Public)).Throws<ArgumentException>().WithParameterName("source");
	}
}
