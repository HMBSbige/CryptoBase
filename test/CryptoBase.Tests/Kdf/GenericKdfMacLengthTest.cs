using CryptoBase.Abstractions.Hashes;
using CryptoBase.Hashes.Sha1;
using CryptoBase.Hashes.Sha384;
using CryptoBase.Hashes.Sha512;
using CryptoBase.Kdf;
using CryptoBase.Macs.Hmac;
using System.Security.Cryptography;
using static CryptoBase.Tests.Kdf.Tls12PrfTest;
using static CryptoBase.Tests.TestUtils;

namespace CryptoBase.Tests.Kdf;

// The other generic KDF tests use HMAC-SHA256; these cover the other MAC lengths.
[GenerateGenericTest(typeof(Sha1HashAlgorithm))]
[GenerateGenericTest(typeof(Sha384HashAlgorithm))]
[GenerateGenericTest(typeof(Sha512HashAlgorithm))]
public class GenericKdfMacLengthTest<THash> where THash : unmanaged, IHmacHashCore<THash>
{
	private static readonly int MacLength = HmacAlgorithm<THash>.MacLength;

	private static readonly HashAlgorithmName HashName =
		typeof(THash) == typeof(Sha1HashAlgorithm) ? HashAlgorithmName.SHA1 :
		typeof(THash) == typeof(Sha384HashAlgorithm) ? HashAlgorithmName.SHA384 :
		typeof(THash) == typeof(Sha512HashAlgorithm) ? HashAlgorithmName.SHA512 :
		throw new NotSupportedException();

	// The output length is blocks * MacLength + extra.
	[Test]
	[Arguments(0, 1)]
	[Arguments(1, -1)]
	[Arguments(1, 0)]
	[Arguments(1, 1)]
	[Arguments(2, 1)]
	[Arguments(255, 0)]
	public async Task HkdfMatchesPlatform(int blocks, int extra)
	{
		byte[] ikm = CreateData(40, 1);
		byte[] salt = CreateData(MacLength + 3, 2);
		byte[] info = CreateData(17, 3);
		byte[] expected = new byte[blocks * MacLength + extra];
		HKDF.DeriveKey(HashName, ikm, expected, salt, info);

		byte[] actual = new byte[expected.Length];
		Hkdf<HmacAlgorithm<THash>>.DeriveKey(ikm, actual, salt, info);

		await Assert.That(actual).IsEquivalentTo(expected, CollectionOrdering.Matching);
	}

	[Test]
	public async Task HkdfRejectsMoreThan255Blocks()
	{
		byte[] output = new byte[255 * MacLength + 1];
		await Assert.That(() => Hkdf<HmacAlgorithm<THash>>.DeriveKey([], output, [], [])).ThrowsExactly<ArgumentOutOfRangeException>().WithParameterName("output");
	}

	[Test]
	[Arguments(0, 1)]
	[Arguments(1, -1)]
	[Arguments(1, 0)]
	[Arguments(1, 1)]
	[Arguments(2, 1)]
	[Arguments(4, 3)]
	public async Task Tls12PrfMatchesReference(int blocks, int extra)
	{
		byte[] secret = CreateData(48, 1);
		byte[] label = "key expansion"u8.ToArray();
		byte[] seed1 = CreateData(32, 2);
		byte[] seed2 = CreateData(32, 3);
		byte[] expected = ReferencePrf(PlatformMac(HashName), secret, label, Concat(seed1, seed2), blocks * MacLength + extra);

		byte[] actual = new byte[expected.Length];
		Tls12Prf<HmacAlgorithm<THash>>.DeriveKey(secret, label, seed1, seed2, actual);

		await Assert.That(actual).IsEquivalentTo(expected, CollectionOrdering.Matching);
	}

	// The output starts inside the first input and reaches the last one.
	[Test]
	[Arguments(1, -1)]
	[Arguments(1, 0)]
	[Arguments(2, 1)]
	public async Task HkdfAllowsEveryInputToOverlapTheOutput(int blocks, int extra)
	{
		int length = blocks * MacLength + extra;
		byte[] buffer = CreateData(Math.Max(18, 3 + length), 4);
		byte[] expected = new byte[length];
		HKDF.DeriveKey(HashName, buffer[..6], expected, buffer[6..12], buffer[12..18]);

		Hkdf<HmacAlgorithm<THash>>.DeriveKey(buffer.AsSpan(0, 6), buffer.AsSpan(3, length), buffer.AsSpan(6, 6), buffer.AsSpan(12, 6));

		await Assert.That(buffer.AsMemory(3, length)).IsEquivalentTo(expected, CollectionOrdering.Matching);
	}

	[Test]
	[Arguments(1, -1)]
	[Arguments(1, 0)]
	[Arguments(2, 1)]
	public async Task Tls12PrfAllowsEveryInputToOverlapTheOutput(int blocks, int extra)
	{
		int length = blocks * MacLength + extra;
		byte[] buffer = CreateData(Math.Max(24, 3 + length), 5);
		byte[] expected = ReferencePrf(PlatformMac(HashName), buffer[..6], buffer[6..12], buffer[12..24], length);

		Tls12Prf<HmacAlgorithm<THash>>.DeriveKey(buffer.AsSpan(0, 6), buffer.AsSpan(6, 6), buffer.AsSpan(12, 6), buffer.AsSpan(18, 6), buffer.AsSpan(3, length));

		await Assert.That(buffer.AsMemory(3, length)).IsEquivalentTo(expected, CollectionOrdering.Matching);
	}
}
