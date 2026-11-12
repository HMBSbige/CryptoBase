using CryptoBase.Hashes.Sha2;
using CryptoBase.Kdf;

namespace CryptoBase.SpeedTest.Catalog;

internal static partial class AlgorithmCatalog
{
	private static AlgorithmEntry[] CreateKdfEntries()
	{
		byte[] salt = TestData.Sequence(32);
		byte[] info = TestData.Sequence(32);
		byte[] label = "master secret"u8.ToArray();
		byte[] seed = TestData.Sequence(64);
		byte[] passwordSalt = TestData.Sequence(16);
		Argon2Parameters second = Argon2Parameters.Rfc9106SecondRecommended;
		Argon2Parameters first = Argon2Parameters.Rfc9106FirstRecommended;

		const string HkdfNotes = "32-byte IKM, salt and info; 32-byte output";
		const string PrfNotes = "48-byte secret, label 'master secret', 64-byte seed; 48-byte output";
		const string SecondNotes = "RFC 9106 second recommended: 64 MiB, t=3, p=4, threads unlimited; 32-byte password, 16-byte salt, 32-byte output";
		const string FirstNotes = "RFC 9106 first recommended: 2 GiB, t=1, p=4, threads unlimited; 32-byte password, 16-byte salt, 32-byte output";

		return
		[
			Kdf("hkdf-sha256", typeof(Hkdf), 32, 32, (ikm, output) => Hkdf.DeriveKey<Sha256Core>(ikm, output, salt, info), HkdfNotes),
			Kdf("hkdf-sha384", typeof(Hkdf), 32, 32, (ikm, output) => Hkdf.DeriveKey<Sha384Core>(ikm, output, salt, info), HkdfNotes),
			Kdf("hkdf-sha512", typeof(Hkdf), 32, 32, (ikm, output) => Hkdf.DeriveKey<Sha512Core>(ikm, output, salt, info), HkdfNotes),
			Kdf("tls12-prf-sha256", typeof(Tls12Prf), 48, 48, (secret, output) => Tls12Prf.DeriveKey<Sha256Core>(secret, label, seed, output), PrfNotes),
			Kdf("tls12-prf-sha384", typeof(Tls12Prf), 48, 48, (secret, output) => Tls12Prf.DeriveKey<Sha384Core>(secret, label, seed, output), PrfNotes),
			Kdf("sm3-kdf", typeof(SM3Kdf), 64, 32, SM3Kdf.DeriveKey, "64-byte secret; 32-byte output"),
			Argon2("argon2id", typeof(Argon2id), (password, output) => Argon2id.DeriveKey(password, passwordSalt, output, second), SecondNotes),
			Argon2("argon2i", typeof(Argon2i), (password, output) => Argon2i.DeriveKey(password, passwordSalt, output, second), SecondNotes),
			Argon2("argon2d", typeof(Argon2d), (password, output) => Argon2d.DeriveKey(password, passwordSalt, output, second), SecondNotes),
			Argon2("argon2id-2g", typeof(Argon2id), (password, output) => Argon2id.DeriveKey(password, passwordSalt, output, first), FirstNotes, isSlow: true)
		];
	}

	/// <param name="implementationType">The type whose method <paramref name="derive" /> calls.</param>
	/// <param name="secretLength">The length of the secret or IKM, which the self-test varies.</param>
	/// <param name="derive">The derivation, with its other inputs fixed.</param>
	/// <param name="notes">The fixed parameters.</param>
	private static AlgorithmEntry Kdf(string name, Type implementationType, int secretLength, int outputLength, KdfFunction derive, string notes)
	{
		return Kdf(name, implementationType, [], secretLength, outputLength, derive, notes, isSlow: false);
	}

	/// <summary>
	/// Creates an entry that derives a 32-byte key from a 32-byte password with Argon2.
	/// </summary>
	private static AlgorithmEntry Argon2(string name, Type implementationType, KdfFunction derive, string notes, bool isSlow = false)
	{
		return Kdf(name, implementationType, [typeof(Argon2Parameters)], 32, 32, derive, notes, isSlow);
	}

	private static AlgorithmEntry Kdf(string name, Type implementationType, ImmutableArray<Type> relatedTypes, int secretLength, int outputLength, KdfFunction derive, string notes, bool isSlow)
	{
		return new AlgorithmEntry
		{
			Name = name,
			Group = AlgorithmGroups.Kdf,
			ImplementationType = implementationType,
			RelatedTypes = relatedTypes,
			Operations = [OperationNames.Derive],
			Notes = notes,
			IsSlow = isSlow,
			CreateWorkload = (_, _) => new KdfWorkload(secretLength, outputLength, derive)
		};
	}
}
