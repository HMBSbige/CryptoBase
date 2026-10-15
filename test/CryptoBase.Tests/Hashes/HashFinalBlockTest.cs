using CryptoBase.Abstractions.Hashes;
using CryptoBase.Hashes;
using CryptoBase.Hashes.Blake2b;
using CryptoBase.Hashes.Blake3;
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
			ReadOnlyMemory<byte> message = source.AsMemory(0, length);
			await Assert.That(Hash<HashAlgorithm<MD5HashAlgorithm>>(message.Span)).IsEquivalentTo(Bcl.MD5.HashData(message.Span), CollectionOrdering.Matching);
			await Assert.That(Hash<HashAlgorithm<Sha1HashAlgorithm>>(message.Span)).IsEquivalentTo(Bcl.SHA1.HashData(message.Span), CollectionOrdering.Matching);
			await Assert.That(Hash<HashAlgorithm<Sha256HashAlgorithm>>(message.Span)).IsEquivalentTo(Bcl.SHA256.HashData(message.Span), CollectionOrdering.Matching);
			await Assert.That(Hash<HashAlgorithm<Sha384HashAlgorithm>>(message.Span)).IsEquivalentTo(Bcl.SHA384.HashData(message.Span), CollectionOrdering.Matching);
			await Assert.That(Hash<HashAlgorithm<Sha512HashAlgorithm>>(message.Span)).IsEquivalentTo(Bcl.SHA512.HashData(message.Span), CollectionOrdering.Matching);
			await Assert.That(Hash<HashAlgorithm<Sha224HashAlgorithm>>(message.Span)).IsEquivalentTo(HashIncrementally<HashAlgorithm<Sha224HashAlgorithm>>(message.Span), CollectionOrdering.Matching);
			await Assert.That(Hash<HashAlgorithm<SM3HashAlgorithm>>(message.Span)).IsEquivalentTo(HashIncrementally<HashAlgorithm<SM3HashAlgorithm>>(message.Span), CollectionOrdering.Matching);
			await Assert.That(Hash<HashAlgorithm<Blake2b256HashAlgorithm>>(message.Span)).IsEquivalentTo(HashIncrementally<HashAlgorithm<Blake2b256HashAlgorithm>>(message.Span), CollectionOrdering.Matching);
			await Assert.That(Hash<HashAlgorithm<Blake2b512HashAlgorithm>>(message.Span)).IsEquivalentTo(HashIncrementally<HashAlgorithm<Blake2b512HashAlgorithm>>(message.Span), CollectionOrdering.Matching);
			await Assert.That(Hash<Blake3HashAlgorithm>(message.Span)).IsEquivalentTo(HashIncrementally<Blake3HashAlgorithm>(message.Span), CollectionOrdering.Matching);
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
				ReadOnlyMemory<byte> message = source.AsMemory(0, length);
				await Assert.That(Mac<MD5HashAlgorithm>(key, message.Span)).IsEquivalentTo(Bcl.HMACMD5.HashData(key, message.Span), CollectionOrdering.Matching);
				await Assert.That(Mac<Sha1HashAlgorithm>(key, message.Span)).IsEquivalentTo(Bcl.HMACSHA1.HashData(key, message.Span), CollectionOrdering.Matching);
				await Assert.That(Mac<Sha256HashAlgorithm>(key, message.Span)).IsEquivalentTo(Bcl.HMACSHA256.HashData(key, message.Span), CollectionOrdering.Matching);
				await Assert.That(Mac<Sha384HashAlgorithm>(key, message.Span)).IsEquivalentTo(Bcl.HMACSHA384.HashData(key, message.Span), CollectionOrdering.Matching);
				await Assert.That(Mac<Sha512HashAlgorithm>(key, message.Span)).IsEquivalentTo(Bcl.HMACSHA512.HashData(key, message.Span), CollectionOrdering.Matching);
				await Assert.That(Mac<Sha224HashAlgorithm>(key, message.Span)).IsEquivalentTo(MacIncrementally<Sha224HashAlgorithm>(key, message.Span), CollectionOrdering.Matching);
				await Assert.That(Mac<SM3HashAlgorithm>(key, message.Span)).IsEquivalentTo(MacIncrementally<SM3HashAlgorithm>(key, message.Span), CollectionOrdering.Matching);
				await Assert.That(Mac<Blake2b256HashAlgorithm>(key, message.Span)).IsEquivalentTo(MacIncrementally<Blake2b256HashAlgorithm>(key, message.Span), CollectionOrdering.Matching);
				await Assert.That(Mac<Blake2b512HashAlgorithm>(key, message.Span)).IsEquivalentTo(MacIncrementally<Blake2b512HashAlgorithm>(key, message.Span), CollectionOrdering.Matching);
			}
		}
	}

	private static byte[] Hash<T>(ReadOnlySpan<byte> message) where T : class, IHashAlgorithm<T>
	{
		byte[] digest = new byte[T.HashLength];
		T.HashData(message, digest);
		return digest;
	}

	// Appends one byte at a time so every block is compressed from the buffer rather than the one-shot multi-block path.
	private static byte[] HashIncrementally<T>(ReadOnlySpan<byte> message) where T : class, IHashAlgorithm<T>
	{
		using T hash = T.Create();

		foreach (byte value in message)
		{
			hash.Append([value]);
		}

		byte[] digest = new byte[T.HashLength];
		hash.GetHashAndReset(digest);
		return digest;
	}

	private static byte[] Mac<T>(ReadOnlySpan<byte> key, ReadOnlySpan<byte> message) where T : unmanaged, IHmacHashCore<T>
	{
		byte[] mac = new byte[HmacAlgorithm<T>.MacLength];
		HmacAlgorithm<T>.Mac(key, message, mac);
		return mac;
	}

	private static byte[] MacIncrementally<T>(ReadOnlySpan<byte> key, ReadOnlySpan<byte> message) where T : unmanaged, IHmacHashCore<T>
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
