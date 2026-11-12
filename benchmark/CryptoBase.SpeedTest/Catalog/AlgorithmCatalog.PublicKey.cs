using CryptoBase.Hpke;
using CryptoBase.Kems.Hybrid;
using CryptoBase.Kems.MLKem;
using CryptoBase.KeyAgreements.Ecdh;
using CryptoBase.KeyAgreements.Xdh;
using CryptoBase.SM2;
using CryptoBase.SM9;

namespace CryptoBase.SpeedTest.Catalog;

internal static partial class AlgorithmCatalog
{
	private static AlgorithmEntry[] CreateKemEntries()
	{
		return
		[
			Kem<MLKem512>("ml-kem-512"),
			Kem<MLKem768>("ml-kem-768"),
			Kem<MLKem1024>("ml-kem-1024"),
			Kem<X25519MLKem768>("x25519mlkem768"),
			Kem<SecP256r1MLKem768>("secp256r1mlkem768"),
			Kem<SecP384r1MLKem1024>("secp384r1mlkem1024"),
			Kem<DhKemP256>("dhkem-p256"),
			Kem<DhKemP384>("dhkem-p384"),
			Kem<DhKemP521>("dhkem-p521"),
			Kem<DhKemX25519>("dhkem-x25519"),
			Kem<DhKemX448>("dhkem-x448"),
			SM9Kem("sm9-kem")
		];
	}

	private static AlgorithmEntry[] CreateKeyAgreementEntries()
	{
		return
		[
			KeyAgreement<X25519>("x25519"),
			KeyAgreement<X448>("x448"),
			KeyAgreement<EcdhP256>("ecdh-p256"),
			KeyAgreement<EcdhP384>("ecdh-p384"),
			KeyAgreement<EcdhP521>("ecdh-p521"),
			KeyAgreement<EcdhSM2>("ecdh-sm2"),
			KeyExchange("sm2-kex", typeof(SM2KeyExchange), [typeof(SM2Key)], static () => new SM2KeyExchangeWorkload(), "initiator: static keys and IDs, 16-byte key, no confirmations"),
			KeyExchange("sm9-kex", typeof(SM9KeyExchange), [typeof(SM9KeyExchangeKey)], static () => new SM9KeyExchangeWorkload(), "keygen: extracts the private key of an ID; initiator: 16-byte key, no confirmations", SM9KeyExtractionWorkload.ForKeyExchange)
		];
	}

	private static AlgorithmEntry[] CreatePublicKeyEncryptionEntries()
	{
		return
		[
			Encryption("sm2-encrypt", typeof(SM2Key), [], static decrypt => new SM2EncryptionWorkload(decrypt), "C1C3C2; 32-byte message"),
			Encryption("sm9-encrypt", typeof(SM9EncryptionMasterKey), [typeof(SM9EncryptionKey)], static decrypt => new SM9EncryptionWorkload(decrypt), "C1C3C2 with the KDF stream cipher; 32-byte message"),
			Hpke<DhKemX25519>("hpke-x25519", HpkeKdfId.HkdfSha256, HpkeAeadId.Aes128Gcm),
			Hpke<DhKemP256>("hpke-p256", HpkeKdfId.HkdfSha256, HpkeAeadId.Aes128Gcm),
			Hpke<DhKemP384>("hpke-p384", HpkeKdfId.HkdfSha384, HpkeAeadId.Aes256Gcm),
			Hpke<DhKemP521>("hpke-p521", HpkeKdfId.HkdfSha512, HpkeAeadId.Aes256Gcm),
			Hpke<DhKemX448>("hpke-x448", HpkeKdfId.HkdfSha512, HpkeAeadId.Aes256Gcm),
			HpkeAuth<DhKemX25519>("hpke-x25519-auth", HpkeKdfId.HkdfSha256, HpkeAeadId.Aes128Gcm),
			HpkeAuth<DhKemP256>("hpke-p256-auth", HpkeKdfId.HkdfSha256, HpkeAeadId.Aes128Gcm),
			HpkeAuth<DhKemP384>("hpke-p384-auth", HpkeKdfId.HkdfSha384, HpkeAeadId.Aes256Gcm),
			HpkeAuth<DhKemP521>("hpke-p521-auth", HpkeKdfId.HkdfSha512, HpkeAeadId.Aes256Gcm),
			HpkeAuth<DhKemX448>("hpke-x448-auth", HpkeKdfId.HkdfSha512, HpkeAeadId.Aes256Gcm)
		];
	}

	private static AlgorithmEntry SM9Kem(string name)
	{
		return new AlgorithmEntry
		{
			Name = name,
			Group = AlgorithmGroups.Kem,
			ImplementationType = typeof(SM9EncryptionMasterKey),
			RelatedTypes = [typeof(SM9EncryptionKey)],
			Operations = [OperationNames.KeyGen, OperationNames.Encapsulate, OperationNames.Decapsulate],
			Notes = "keygen: extracts the private key of an ID; encapsulates to an ID under the master public key; 32-byte key",
			CreateWorkload = static (operation, _) => operation switch
			{
				OperationNames.KeyGen => SM9KeyExtractionWorkload.ForEncryption(),
				OperationNames.Encapsulate => new SM9KemWorkload(decapsulate: false),
				OperationNames.Decapsulate => new SM9KemWorkload(decapsulate: true),
				_ => throw new ArgumentOutOfRangeException(nameof(operation), operation, null)
			}
		};
	}

	/// <summary>
	/// Creates an entry whose derive operation is one party's side of a whole key exchange.
	/// </summary>
	/// <param name="createKeyGenWorkload">Creates the workload of key generation, if the entry measures it.</param>
	private static AlgorithmEntry KeyExchange(string name, Type implementationType, ImmutableArray<Type> relatedTypes, Func<Workload> createWorkload, string notes, Func<Workload>? createKeyGenWorkload = null)
	{
		return new AlgorithmEntry
		{
			Name = name,
			Group = AlgorithmGroups.Kex,
			ImplementationType = implementationType,
			RelatedTypes = relatedTypes,
			Operations = createKeyGenWorkload is null ? [OperationNames.Derive] : [OperationNames.KeyGen, OperationNames.Derive],
			Notes = notes,
			CreateWorkload = (operation, _) => operation switch
			{
				OperationNames.KeyGen when createKeyGenWorkload is not null => createKeyGenWorkload(),
				OperationNames.Derive => createWorkload(),
				_ => throw new ArgumentOutOfRangeException(nameof(operation), operation, null)
			}
		};
	}

	/// <param name="createWorkload">Creates the workload of decryption if its argument is <see langword="true" />, and of encryption otherwise.</param>
	private static AlgorithmEntry Encryption(string name, Type implementationType, ImmutableArray<Type> relatedTypes, Func<bool, Workload> createWorkload, string notes)
	{
		return new AlgorithmEntry
		{
			Name = name,
			Group = AlgorithmGroups.Pke,
			ImplementationType = implementationType,
			RelatedTypes = relatedTypes,
			Operations = [OperationNames.Encrypt, OperationNames.Decrypt],
			Notes = notes,
			CreateWorkload = (operation, _) => createWorkload(IsDecrypt(operation))
		};
	}

	/// <summary>
	/// Creates an entry that encrypts one message to a public key with HPKE in the base mode: a new context and one seal or open per operation.
	/// </summary>
	private static AlgorithmEntry Hpke<TKem>(string name, HpkeKdfId kdf, HpkeAeadId aead) where TKem : class, IHpkeKem<TKem>
	{
		return Hpke(name, typeof(TKem), "base mode", kdf, aead, decrypt => new HpkeWorkload<TKem>(kdf, aead, decrypt));
	}

	/// <summary>
	/// Creates an entry like <see cref="Hpke{TKem}" /> in the auth mode, which authenticates the sender with its key pair.
	/// </summary>
	private static AlgorithmEntry HpkeAuth<TKem>(string name, HpkeKdfId kdf, HpkeAeadId aead) where TKem : class, IHpkeAuthKem<TKem>
	{
		return Hpke(name, typeof(TKem), "auth mode", kdf, aead, decrypt => new HpkeAuthWorkload<TKem>(kdf, aead, decrypt));
	}

	private static AlgorithmEntry Hpke(string name, Type kemType, string mode, HpkeKdfId kdf, HpkeAeadId aead, Func<bool, Workload> createWorkload)
	{
		string kdfName = kdf switch
		{
			HpkeKdfId.HkdfSha256 => "HKDF-SHA256",
			HpkeKdfId.HkdfSha384 => "HKDF-SHA384",
			HpkeKdfId.HkdfSha512 => "HKDF-SHA512",
			_ => throw new ArgumentOutOfRangeException(nameof(kdf), kdf, null)
		};

		string aeadName = aead switch
		{
			HpkeAeadId.Aes128Gcm => "AES-128-GCM",
			HpkeAeadId.Aes256Gcm => "AES-256-GCM",
			HpkeAeadId.ChaCha20Poly1305 => "ChaCha20-Poly1305",
			_ => throw new ArgumentOutOfRangeException(nameof(aead), aead, null)
		};

		return Encryption
		(
			name,
			typeof(HpkeSenderContext),
			[typeof(HpkeRecipientContext), typeof(HpkeAlgorithmExtensions), kemType],
			createWorkload,
			$"{mode}, {kdfName}, {aeadName}; empty info and associated data; 32-byte message"
		);
	}
}
