using CryptoBase.Ciphers.Modes;
using CryptoBase.Ciphers.Padding;
using CryptoBase.Ciphers.Streams;
using CryptoBase.Encodings;
using CryptoBase.Kdf;
using CryptoBase.Otp;
using CryptoBase.Signatures;
using CryptoBase.SpeedTest.Catalog;
using static CryptoBase.Tests.TestUtils;

namespace CryptoBase.Tests;

// The speed test lists its algorithms by hand, so this makes each new public type of the library either a catalog entry or a stated exclusion.
public class SpeedTestCatalogTest
{
	private static readonly Dictionary<Type, string> Excluded = new()
	{
		[typeof(CpuIdUtils)] = "Detects processor features; not an algorithm.",
		[typeof(Base32Encoding)] = "A text encoding, not cryptography.",
		[typeof(SymmetricPadding)] = "Block padding, which costs nothing next to the ciphers it pads.",
		[typeof(XtsMode)] = "Static helpers of XtsMode<TBlockCipher>, which aes-*-xts measure.",
		[typeof(SnuffleCipher)] = "The abstract base of the Salsa20 and ChaCha20 ciphers, which their entries measure.",
		[typeof(Hkdf<>)] = "HKDF over a chosen HMAC; hkdf-* measure the same algorithm through Hkdf.",
		[typeof(Tls12Prf<>)] = "The TLS 1.2 PRF over a chosen HMAC; tls12-prf-* measure the same algorithm through Tls12Prf.",
		[typeof(Argon2PasswordHasher)] = "PHC strings around Argon2, whose cost argon2* measure.",
		[typeof(SignatureKey)] = "Imports keys of any signature algorithm; the algorithms themselves have entries.",
		[typeof(Hotp<>)] = "One-time passwords: one HMAC of a counter, which hmac-* measure.",
		[typeof(Totp<>)] = "One-time passwords: one HMAC of a counter, which hmac-* measure.",
		[typeof(OtpCodeFormat)] = "A parameter of the one-time passwords.",
		[typeof(TotpParameters)] = "A parameter of the one-time passwords."
	};

	[Test]
	public async Task EveryPublicTypeIsCatalogedOrExcluded()
	{
		SkipUnlessJit();
		HashSet<Type> cataloged = CatalogedTypes();
		Type[] missing = [.. LibraryTypes().Where(type => !cataloged.Contains(type) && !Excluded.ContainsKey(type))];

		await Assert.That(missing).IsEmpty();
	}

	[Test]
	public async Task NoExclusionIsCatalogedOrSkipped()
	{
		SkipUnlessJit();
		HashSet<Type> cataloged = CatalogedTypes();
		HashSet<Type> libraryTypes = [.. LibraryTypes()];

		using (Assert.Multiple())
		{
			await Assert.That(Excluded.Keys.Where(cataloged.Contains)).IsEmpty();
			await Assert.That(Excluded.Keys.Where(type => !libraryTypes.Contains(type))).IsEmpty();
		}
	}

	/// <summary>
	/// Gets the public types of the core library, but for those that are measured through others or are not algorithms by their kind: enums, interfaces, delegates and nested types.
	/// </summary>
	private static IEnumerable<Type> LibraryTypes()
	{
		return typeof(CpuIdUtils).Assembly.GetExportedTypes().Where(static type => type is { IsEnum: false, IsInterface: false, IsNested: false } && !type.IsSubclassOf(typeof(Delegate)));
	}

	private static HashSet<Type> CatalogedTypes()
	{
		HashSet<Type> types = [];

		foreach (AlgorithmEntry entry in AlgorithmCatalog.Entries)
		{
			Add(entry.ImplementationType);

			foreach (Type type in entry.RelatedTypes)
			{
				Add(type);
			}
		}

		return types;

		void Add(Type type)
		{
			if (!types.Add(type) || !type.IsGenericType)
			{
				return;
			}

			types.Add(type.GetGenericTypeDefinition());

			foreach (Type argument in type.GetGenericArguments())
			{
				Add(argument);
			}
		}
	}
}
