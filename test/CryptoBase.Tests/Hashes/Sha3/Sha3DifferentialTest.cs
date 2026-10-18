using CryptoBase.Abstractions.Hashes;
using CryptoBase.Hashes;
using CryptoBase.Hashes.Sha3;
using CryptoBase.Macs.Hmac;

namespace CryptoBase.Tests.Hashes.Sha3;

// Random messages of up to 4 * rate + 1 bytes, appended in random pieces that include empty ones, against the oracles in Sha3TestUtils.
public class Sha3DifferentialTest
{
	private const int MessageCount = 200;
	private const int MessagesPerKey = 40;

	public static IEnumerable<int> HashLengths => [28, 32, 48, 64];

	[Test]
	[MethodDataSource(nameof(HashLengths))]
	public Task RandomMessagesMatchOracle(int hashLength)
	{
		return hashLength switch
		{
			28 => VerifyHashes<Sha3_224HashAlgorithm>(),
			32 => VerifyHashes<Sha3_256HashAlgorithm>(),
			48 => VerifyHashes<Sha3_384HashAlgorithm>(),
			64 => VerifyHashes<Sha3_512HashAlgorithm>(),
			_ => throw new ArgumentOutOfRangeException(nameof(hashLength))
		};
	}

	[Test]
	[MethodDataSource(nameof(HashLengths))]
	public Task RandomHmacsMatchOracle(int hashLength)
	{
		return hashLength switch
		{
			28 => VerifyHmacs<Sha3_224HashAlgorithm>(),
			32 => VerifyHmacs<Sha3_256HashAlgorithm>(),
			48 => VerifyHmacs<Sha3_384HashAlgorithm>(),
			64 => VerifyHmacs<Sha3_512HashAlgorithm>(),
			_ => throw new ArgumentOutOfRangeException(nameof(hashLength))
		};
	}

	private static async Task VerifyHashes<T>() where T : unmanaged, IHmacHashCore<T>
	{
		int rate = T.HmacBlockSize;
		Random random = new(T.HashLength);
		byte[] digest = new byte[T.HashLength];

		using HashAlgorithm<T> hashAlgorithm = HashAlgorithm<T>.Create();

		for (int i = 0; i < MessageCount; ++i)
		{
			byte[] message = RandomBytes(random, random.Next(4 * rate + 2));
			byte[] expected = Sha3TestUtils.Hash(T.HashLength, message);

			HashAlgorithm<T>.HashData(message, digest);
			await Assert.That(digest).IsEquivalentTo(expected, CollectionOrdering.Matching).Because($"one-shot, {message.Length}-byte message");

			foreach ((int offset, int length) in RandomPieces(random, message.Length, rate))
			{
				hashAlgorithm.Append(message.AsSpan(offset, length));
			}

			hashAlgorithm.GetHashAndReset(digest);
			await Assert.That(digest).IsEquivalentTo(expected, CollectionOrdering.Matching).Because($"incremental, {message.Length}-byte message");
		}
	}

	private static async Task VerifyHmacs<T>() where T : unmanaged, IHmacHashCore<T>
	{
		int rate = T.HmacBlockSize;
		Random random = new(T.HashLength);
		byte[] mac = new byte[HmacAlgorithm<T>.MacLength];

		// HMAC zero-pads keys up to the block size and hashes longer ones first, so the lengths straddle the rate.
		foreach (int keyLength in (int[])[0, 1, T.HashLength, rate - 1, rate, rate + 1, 2 * rate + 3])
		{
			byte[] key = RandomBytes(random, keyLength);

			using HmacAlgorithm<T> hmac = HmacAlgorithm<T>.Create(key);

			for (int i = 0; i < MessagesPerKey; ++i)
			{
				byte[] message = RandomBytes(random, random.Next(4 * rate + 2));
				byte[] expected = Sha3TestUtils.Hmac(T.HashLength, key, message);

				HmacAlgorithm<T>.Mac(key, message, mac);
				await Assert.That(mac).IsEquivalentTo(expected, CollectionOrdering.Matching).Because($"one-shot, {keyLength}-byte key, {message.Length}-byte message");

				foreach ((int offset, int length) in RandomPieces(random, message.Length, rate))
				{
					hmac.Append(message.AsSpan(offset, length));
				}

				hmac.GetMacAndReset(mac);
				await Assert.That(mac).IsEquivalentTo(expected, CollectionOrdering.Matching).Because($"incremental, {keyLength}-byte key, {message.Length}-byte message");
			}
		}
	}

	private static byte[] RandomBytes(Random random, int length)
	{
		byte[] bytes = new byte[length];
		random.NextBytes(bytes);
		return bytes;
	}

	// Pieces range from empty to just over two blocks, so they start and end anywhere within a block or span several.
	private static List<(int Offset, int Length)> RandomPieces(Random random, int totalLength, int rate)
	{
		List<(int Offset, int Length)> pieces = [];

		for (int offset = 0; offset < totalLength;)
		{
			int length = Math.Min(random.Next(2 * rate + 2), totalLength - offset);
			pieces.Add((offset, length));
			offset += length;
		}

		return pieces;
	}
}
