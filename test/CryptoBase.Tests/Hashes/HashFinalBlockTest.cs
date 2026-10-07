using CryptoBase.Abstractions.Hashes;
using CryptoBase.Hashes;
using CryptoBase.Hashes.MD5;
using CryptoBase.Hashes.Sha1;
using CryptoBase.Hashes.Sha224;
using CryptoBase.Hashes.Sha256;
using CryptoBase.Hashes.Sha384;
using CryptoBase.Hashes.Sha512;
using CryptoBase.Hashes.SM3;
using CryptoBase.Macs.Hmac;
using static CryptoBase.Tests.TestUtils;
using Bcl = System.Security.Cryptography;

namespace CryptoBase.Tests.Hashes;

public class HashFinalBlockTest
{
	private const int MaxLength = 300;
	private static readonly int[] KeyLengths = [0, 1, 31, 32, 63, 64, 65, 127, 128, 129, 200];

	[Test]
	public async Task OneShotHashesMatchReferenceAtEveryLength()
	{
		byte[] source = CreateDeterministicSource(MaxLength);

		for (int length = 0; length <= MaxLength; ++length)
		{
			byte[] message = source.AsSpan(0, length).ToArray();
			await Assert.That(Hash<MD5HashAlgorithm>(message)).IsEquivalentTo(Bcl.MD5.HashData(message), CollectionOrdering.Matching);
			await Assert.That(Hash<Sha1HashAlgorithm>(message)).IsEquivalentTo(Bcl.SHA1.HashData(message), CollectionOrdering.Matching);
			await Assert.That(Hash<Sha256HashAlgorithm>(message)).IsEquivalentTo(Bcl.SHA256.HashData(message), CollectionOrdering.Matching);
			await Assert.That(Hash<Sha384HashAlgorithm>(message)).IsEquivalentTo(Bcl.SHA384.HashData(message), CollectionOrdering.Matching);
			await Assert.That(Hash<Sha512HashAlgorithm>(message)).IsEquivalentTo(Bcl.SHA512.HashData(message), CollectionOrdering.Matching);
			await Assert.That(Hash<Sha224HashAlgorithm>(message)).IsEquivalentTo(HashIncrementally<Sha224HashAlgorithm>(message), CollectionOrdering.Matching);
			await Assert.That(Hash<SM3HashAlgorithm>(message)).IsEquivalentTo(HashIncrementally<SM3HashAlgorithm>(message), CollectionOrdering.Matching);
		}
	}

	[Test]
	public async Task OneShotHmacMatchesReferenceAtEveryLength()
	{
		byte[] source = CreateDeterministicSource(MaxLength);

		foreach (int keyLength in KeyLengths)
		{
			byte[] key = CreateDeterministicSource(keyLength + 1).AsSpan(1).ToArray();

			for (int length = 0; length <= MaxLength; ++length)
			{
				byte[] message = source.AsSpan(0, length).ToArray();
				await Assert.That(Mac<MD5HashAlgorithm>(key, message)).IsEquivalentTo(Bcl.HMACMD5.HashData(key, message), CollectionOrdering.Matching);
				await Assert.That(Mac<Sha1HashAlgorithm>(key, message)).IsEquivalentTo(Bcl.HMACSHA1.HashData(key, message), CollectionOrdering.Matching);
				await Assert.That(Mac<Sha256HashAlgorithm>(key, message)).IsEquivalentTo(Bcl.HMACSHA256.HashData(key, message), CollectionOrdering.Matching);
				await Assert.That(Mac<Sha384HashAlgorithm>(key, message)).IsEquivalentTo(Bcl.HMACSHA384.HashData(key, message), CollectionOrdering.Matching);
				await Assert.That(Mac<Sha512HashAlgorithm>(key, message)).IsEquivalentTo(Bcl.HMACSHA512.HashData(key, message), CollectionOrdering.Matching);
				await Assert.That(Mac<Sha224HashAlgorithm>(key, message)).IsEquivalentTo(MacIncrementally<Sha224HashAlgorithm>(key, message), CollectionOrdering.Matching);
				await Assert.That(Mac<SM3HashAlgorithm>(key, message)).IsEquivalentTo(MacIncrementally<SM3HashAlgorithm>(key, message), CollectionOrdering.Matching);
			}
		}
	}

	private static byte[] Hash<T>(ReadOnlySpan<byte> message) where T : unmanaged, IHashCore<T>
	{
		byte[] digest = new byte[HashAlgorithm<T>.HashLength];
		HashAlgorithm<T>.HashData(message, digest);
		return digest;
	}

	// Appends one byte at a time so every block is compressed from the buffer rather than the one-shot multi-block path.
	private static byte[] HashIncrementally<T>(ReadOnlySpan<byte> message) where T : unmanaged, IHashCore<T>
	{
		using HashAlgorithm<T> hash = HashAlgorithm<T>.Create();

		foreach (byte value in message)
		{
			hash.Append([value]);
		}

		byte[] digest = new byte[HashAlgorithm<T>.HashLength];
		hash.GetHashAndReset(digest);
		return digest;
	}

	private static byte[] Mac<T>(byte[] key, byte[] message) where T : unmanaged, IHmacHashCore<T>
	{
		byte[] mac = new byte[HmacAlgorithm<T>.MacLength];
		HmacAlgorithm<T>.Mac(key, message, mac);
		return mac;
	}

	private static byte[] MacIncrementally<T>(byte[] key, byte[] message) where T : unmanaged, IHmacHashCore<T>
	{
		using HmacAlgorithm<T> hmac = HmacAlgorithm<T>.Create(key);

		foreach (byte value in message)
		{
			hmac.Append([value]);
		}

		byte[] mac = new byte[HmacAlgorithm<T>.MacLength];
		hmac.GetMacAndReset(mac);
		return mac;
	}
}
