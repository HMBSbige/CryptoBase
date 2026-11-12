using CryptoBase.Abstractions.Signatures;
using CryptoBase.Signatures.Ecdsa;
using CryptoBase.Signatures.EdDsa;
using CryptoBase.Signatures.MLDsa;
using CryptoBase.Signatures.Rsa;
using CryptoBase.SM2;
using CryptoBase.SM9;

namespace CryptoBase.SpeedTest.Catalog;

internal static partial class AlgorithmCatalog
{
	private static AlgorithmEntry[] CreateSignatureEntries()
	{
		return
		[
			RsaSignature("rsa-2048", 2048, SignatureAlgorithm.RsaPkcs1Sha256),
			RsaSignature("rsa-3072", 3072, SignatureAlgorithm.RsaPkcs1Sha256),
			RsaSignature("rsa-4096", 4096, SignatureAlgorithm.RsaPkcs1Sha256),
			RsaSignature("rsa-2048-pss", 2048, SignatureAlgorithm.RsaPssSha256),
			RsaSignature("rsa-3072-pss", 3072, SignatureAlgorithm.RsaPssSha256),
			RsaSignature("rsa-4096-pss", 4096, SignatureAlgorithm.RsaPssSha256),
			RsaKeyGeneration("rsa-2048-keygen", 2048),
			RsaKeyGeneration("rsa-3072-keygen", 3072),
			RsaKeyGeneration("rsa-4096-keygen", 4096),
			Signature("ecdsa-p256", SignatureAlgorithm.EcdsaSha256, EcdsaP256.GenerateKey, "SHA-256; 32-byte message"),
			Signature("ecdsa-p384", SignatureAlgorithm.EcdsaSha384, EcdsaP384.GenerateKey, "SHA-384; 32-byte message"),
			Signature("ecdsa-p521", SignatureAlgorithm.EcdsaSha512, EcdsaP521.GenerateKey, "SHA-512; 32-byte message"),
			Signature("ed25519", SignatureAlgorithm.Ed25519, Ed25519.GenerateKey, "32-byte message"),
			Signature("ed448", SignatureAlgorithm.Ed448, Ed448.GenerateKey, "empty context; 32-byte message"),
			Signature("ml-dsa-44", SignatureAlgorithm.MLDsa44, MLDsa44.GenerateKey, "empty context; 32-byte message"),
			Signature("ml-dsa-65", SignatureAlgorithm.MLDsa65, MLDsa65.GenerateKey, "empty context; 32-byte message"),
			Signature("ml-dsa-87", SignatureAlgorithm.MLDsa87, MLDsa87.GenerateKey, "empty context; 32-byte message"),
			Signature("sm2-sign", SignatureAlgorithm.SM2SM3, SM2Key.GenerateKey, "SM3 with the default ID; 32-byte message"),
			SM9Signature("sm9-sign")
		];
	}

	private static AlgorithmEntry Signature<T>(string name, SignatureAlgorithm algorithm, Func<T> generateKey, string notes) where T : class, ISignatureKey<T>
	{
		return Signature(name, algorithm, generateKey, [OperationNames.KeyGen, OperationNames.Sign, OperationNames.Verify], notes);
	}

	/// <summary>
	/// Creates an entry that signs and verifies with the built-in key of <paramref name="modulusBits" /> bits, so that no key is generated at start-up.
	/// </summary>
	private static AlgorithmEntry RsaSignature(string name, int modulusBits, SignatureAlgorithm algorithm)
	{
		string padding = algorithm switch
		{
			SignatureAlgorithm.RsaPkcs1Sha256 => "PKCS #1 v1.5 with SHA-256",
			SignatureAlgorithm.RsaPssSha256 => "PSS with SHA-256, MGF1 with SHA-256 and a 32-byte salt",
			_ => throw new ArgumentOutOfRangeException(nameof(algorithm), algorithm, null)
		};

		return Signature
		(
			name,
			algorithm,
			() => RsaKey.ImportPkcs8PrivateKey(RsaTestKeys.GetPkcs8PrivateKey(modulusBits)),
			[OperationNames.Sign, OperationNames.Verify],
			$"{padding}; fixed built-in key; 32-byte message; keygen: see rsa-{modulusBits}-keygen"
		);
	}

	private static AlgorithmEntry RsaKeyGeneration(string name, int modulusBits)
	{
		return Signature(name, SignatureAlgorithm.RsaPkcs1Sha256, () => RsaKey.GenerateKey(modulusBits), [OperationNames.KeyGen], "public exponent 65537", isSlow: true);
	}

	private static AlgorithmEntry Signature<T>(string name, SignatureAlgorithm algorithm, Func<T> createKey, ImmutableArray<string> operations, string notes, bool isSlow = false) where T : class, ISignatureKey<T>
	{
		return new AlgorithmEntry
		{
			Name = name,
			Group = AlgorithmGroups.Sign,
			ImplementationType = typeof(T),
			Operations = operations,
			Notes = notes,
			IsSlow = isSlow,
			CreateWorkload = (operation, _) => new SignatureWorkload<T>
			(
				operation switch
				{
					OperationNames.KeyGen => SignatureOperation.KeyGen,
					OperationNames.Sign => SignatureOperation.Sign,
					OperationNames.Verify => SignatureOperation.Verify,
					_ => throw new ArgumentOutOfRangeException(nameof(operation), operation, null)
				},
				algorithm,
				createKey
			)
		};
	}

	private static AlgorithmEntry SM9Signature(string name)
	{
		return new AlgorithmEntry
		{
			Name = name,
			Group = AlgorithmGroups.Sign,
			ImplementationType = typeof(SM9SignatureKey),
			RelatedTypes = [typeof(SM9SignatureMasterKey)],
			Operations = [OperationNames.KeyGen, OperationNames.Sign, OperationNames.Verify],
			Notes = "keygen: extracts the private key of an ID; verify: with the master public key and the ID of the signer; 32-byte message",
			CreateWorkload = static (operation, _) => operation switch
			{
				OperationNames.KeyGen => SM9KeyExtractionWorkload.ForSignature(),
				OperationNames.Sign => new SM9SignatureWorkload(verify: false),
				OperationNames.Verify => new SM9SignatureWorkload(verify: true),
				_ => throw new ArgumentOutOfRangeException(nameof(operation), operation, null)
			}
		};
	}
}
