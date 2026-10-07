using CryptoBase.Abstractions.Hashes;
using CryptoBase.Hashes;
using CryptoBase.Hashes.Sha1;
using CryptoBase.Hashes.Sha256;
using CryptoBase.Hashes.Sha384;
using CryptoBase.Hashes.Sha512;
using CryptoBase.Kdf;
using System.Security.Cryptography;
using static CryptoBase.Tests.TestUtils;

namespace CryptoBase.Tests.Kdf;

public class HkdfTest
{
	[Test]
	public async Task ExpandMatchesPlatformAcrossMessageBoundaries()
	{
		await VerifyExpandSweep<Sha1HashAlgorithm>(HashAlgorithmName.SHA1);
		await VerifyExpandSweep<Sha256HashAlgorithm>(HashAlgorithmName.SHA256);
		await VerifyExpandSweep<Sha384HashAlgorithm>(HashAlgorithmName.SHA384);
		await VerifyExpandSweep<Sha512HashAlgorithm>(HashAlgorithmName.SHA512);
	}

	private static async Task VerifyExpandSweep<THash>(HashAlgorithmName name) where THash : unmanaged, IHmacHashCore<THash>
	{
		int hashLength = THash.HashLength;
		byte[] prk = CreateDeterministicSource(hashLength);
		IEnumerable<int> infoLengths = Enumerable.Range(0, 141).Append(300);

		foreach (int infoLength in infoLengths)
		{
			byte[] info = CreateDeterministicSource(infoLength);

			foreach (int outputLength in new[] { 1, hashLength - 1, hashLength, hashLength + 1, 2 * hashLength + 3 })
			{
				byte[] expected = new byte[outputLength];
				byte[] actual = new byte[outputLength];
				HKDF.Expand(name, prk, expected, info);
				Hkdf.Expand<THash>(prk, actual, info);

				await Assert.That(actual).IsEquivalentTo(expected, CollectionOrdering.Matching);
			}
		}
	}

	[Test]
	public async Task RejectsInvalidLengthsWithoutWriting()
	{
		int hashLength = HashAlgorithm<Sha256HashAlgorithm>.HashLength;
		byte[] ikm = CreateData(37, 3);
		byte[] salt = CreateData(19, 5);
		byte[] info = CreateData(11, 7);
		byte[] prk = new byte[hashLength];
		byte[] shortPrk = new byte[hashLength - 1];
		PrepareDestination(shortPrk);
		byte[] oversizedOutput = new byte[checked(255 * hashLength + 1)];
		PrepareDestination(oversizedOutput);

		await Assert.That(() => Hkdf.Extract<Sha256HashAlgorithm>(ikm, salt, shortPrk))
			.ThrowsExactly<ArgumentOutOfRangeException>();
		await Assert.That(shortPrk).All(static value => value is DestinationSentinel);

		await Assert.That(() => Hkdf.Expand<Sha256HashAlgorithm>(prk, Array.Empty<byte>(), info))
			.ThrowsExactly<ArgumentOutOfRangeException>();

		byte[] output = [DestinationSentinel];
		await Assert.That(() => Hkdf.Expand<Sha256HashAlgorithm>(shortPrk, output, info))
			.ThrowsExactly<ArgumentOutOfRangeException>();
		await Assert.That(output[0]).IsEqualTo(DestinationSentinel);

		await Assert.That(() => Hkdf.Expand<Sha256HashAlgorithm>(prk, oversizedOutput, info))
			.ThrowsExactly<ArgumentOutOfRangeException>();
		await Assert.That(oversizedOutput).All(static value => value is DestinationSentinel);

		await Assert.That(() => Hkdf.DeriveKey<Sha256HashAlgorithm>(ikm, Array.Empty<byte>(), salt, info))
			.ThrowsExactly<ArgumentOutOfRangeException>();

		await Assert.That(() => Hkdf.DeriveKey<Sha256HashAlgorithm>(ikm, oversizedOutput, salt, info))
			.ThrowsExactly<ArgumentOutOfRangeException>();
		await Assert.That(oversizedOutput).All(static value => value is DestinationSentinel);
	}

	[Test]
	[Arguments(0, 0)]
	[Arguments(0, 10)]
	[Arguments(10, 0)]
	public async Task SupportsPrkAndOutputOverlap(int prkOffset, int outputOffset)
	{
		const int outputLength = 73;
		byte[] prk = CreateData(HashAlgorithm<Sha256HashAlgorithm>.HashLength, 13);
		byte[] info = CreateData(23, 19);
		byte[] expected = new byte[outputLength];
		HKDF.Expand(HashAlgorithmName.SHA256, prk, expected, info);

		byte[] buffer = CreateOverlapBuffer(prk, prkOffset, outputOffset, outputLength);
		Hkdf.Expand<Sha256HashAlgorithm>(buffer.AsSpan(prkOffset, prk.Length), buffer.AsSpan(outputOffset, outputLength), info);

		await Assert.That(buffer.AsMemory(outputOffset, outputLength)).IsEquivalentTo(expected, CollectionOrdering.Matching);
	}

	[Test]
	[Arguments(0, 0)]
	[Arguments(0, 10)]
	[Arguments(10, 0)]
	public async Task SupportsIkmAndPrkOverlap(int ikmOffset, int prkOffset)
	{
		int hashLength = HashAlgorithm<Sha256HashAlgorithm>.HashLength;
		byte[] ikm = CreateData(73, 11);
		byte[] salt = CreateData(37, 29);
		byte[] expected = new byte[hashLength];
		HKDF.Extract(HashAlgorithmName.SHA256, ikm, salt, expected);

		byte[] buffer = CreateOverlapBuffer(ikm, ikmOffset, prkOffset, hashLength);
		int written = Hkdf.Extract<Sha256HashAlgorithm>(buffer.AsSpan(ikmOffset, ikm.Length), salt, buffer.AsSpan(prkOffset, hashLength));

		await Assert.That(written).IsEqualTo(hashLength);
		await Assert.That(buffer.AsMemory(prkOffset, hashLength)).IsEquivalentTo(expected, CollectionOrdering.Matching);
	}

	[Test]
	[Arguments(0, 0)]
	[Arguments(0, 10)]
	[Arguments(10, 0)]
	public async Task SupportsSaltAndPrkOverlap(int saltOffset, int prkOffset)
	{
		int hashLength = HashAlgorithm<Sha256HashAlgorithm>.HashLength;
		byte[] ikm = CreateData(73, 11);
		byte[] salt = CreateData(37, 29);
		byte[] expected = new byte[hashLength];
		HKDF.Extract(HashAlgorithmName.SHA256, ikm, salt, expected);

		byte[] buffer = CreateOverlapBuffer(salt, saltOffset, prkOffset, hashLength);
		int written = Hkdf.Extract<Sha256HashAlgorithm>(ikm, buffer.AsSpan(saltOffset, salt.Length), buffer.AsSpan(prkOffset, hashLength));

		await Assert.That(written).IsEqualTo(hashLength);
		await Assert.That(buffer.AsMemory(prkOffset, hashLength)).IsEquivalentTo(expected, CollectionOrdering.Matching);
	}

	[Test]
	[Arguments(32, 0, 0)]
	[Arguments(64, 0, 0)]
	[Arguments(32, 0, 10)]
	[Arguments(32, 10, 0)]
	[Arguments(97, 0, 0)]
	[Arguments(97, 0, 10)]
	[Arguments(97, 10, 0)]
	public async Task SupportsInfoAndOutputOverlap(int outputLength, int infoOffset, int outputOffset)
	{
		byte[] prk = CreateData(HashAlgorithm<Sha256HashAlgorithm>.HashLength, 13);
		byte[] info = CreateData(257, 19);
		byte[] expected = new byte[outputLength];
		HKDF.Expand(HashAlgorithmName.SHA256, prk, expected, info);

		byte[] buffer = CreateOverlapBuffer(info, infoOffset, outputOffset, outputLength);
		Hkdf.Expand<Sha256HashAlgorithm>(prk, buffer.AsSpan(outputOffset, outputLength), buffer.AsSpan(infoOffset, info.Length));

		await Assert.That(buffer.AsMemory(outputOffset, outputLength)).IsEquivalentTo(expected, CollectionOrdering.Matching);
	}

	[Test]
	[Arguments(0, 0)]
	[Arguments(0, 10)]
	[Arguments(10, 0)]
	public async Task SupportsIkmAndOutputOverlapInDeriveKey(int ikmOffset, int outputOffset)
	{
		const int outputLength = 97;
		byte[] ikm = CreateData(73, 11);
		byte[] salt = CreateData(37, 29);
		byte[] info = CreateData(23, 47);
		byte[] expected = new byte[outputLength];
		HKDF.DeriveKey(HashAlgorithmName.SHA256, ikm, expected, salt, info);

		byte[] buffer = CreateOverlapBuffer(ikm, ikmOffset, outputOffset, outputLength);
		Hkdf.DeriveKey<Sha256HashAlgorithm>(buffer.AsSpan(ikmOffset, ikm.Length), buffer.AsSpan(outputOffset, outputLength), salt, info);

		await Assert.That(buffer.AsMemory(outputOffset, outputLength)).IsEquivalentTo(expected, CollectionOrdering.Matching);
	}

	[Test]
	[Arguments(0, 0)]
	[Arguments(0, 10)]
	[Arguments(10, 0)]
	public async Task SupportsSaltAndOutputOverlapInDeriveKey(int saltOffset, int outputOffset)
	{
		const int outputLength = 97;
		byte[] ikm = CreateData(73, 11);
		byte[] salt = CreateData(37, 29);
		byte[] info = CreateData(23, 47);
		byte[] expected = new byte[outputLength];
		HKDF.DeriveKey(HashAlgorithmName.SHA256, ikm, expected, salt, info);

		byte[] buffer = CreateOverlapBuffer(salt, saltOffset, outputOffset, outputLength);
		Hkdf.DeriveKey<Sha256HashAlgorithm>(ikm, buffer.AsSpan(outputOffset, outputLength), buffer.AsSpan(saltOffset, salt.Length), info);

		await Assert.That(buffer.AsMemory(outputOffset, outputLength)).IsEquivalentTo(expected, CollectionOrdering.Matching);
	}

	[Test]
	[Arguments(32, 0, 0)]
	[Arguments(32, 0, 10)]
	[Arguments(32, 10, 0)]
	[Arguments(97, 0, 0)]
	[Arguments(97, 0, 10)]
	[Arguments(97, 10, 0)]
	public async Task SupportsInfoAndOutputOverlapInDeriveKey(int outputLength, int infoOffset, int outputOffset)
	{
		byte[] ikm = CreateData(73, 11);
		byte[] salt = CreateData(37, 29);
		byte[] info = CreateData(257, 47);
		byte[] expected = new byte[outputLength];
		HKDF.DeriveKey(HashAlgorithmName.SHA256, ikm, expected, salt, info);

		byte[] buffer = CreateOverlapBuffer(info, infoOffset, outputOffset, outputLength);
		Hkdf.DeriveKey<Sha256HashAlgorithm>(ikm, buffer.AsSpan(outputOffset, outputLength), salt, buffer.AsSpan(infoOffset, info.Length));

		await Assert.That(buffer.AsMemory(outputOffset, outputLength)).IsEquivalentTo(expected, CollectionOrdering.Matching);
	}

	[Test]
	[Arguments(257)]
	public async Task SupportsExactInfoAndOutputOverlap(int infoLength)
	{
		const int outputLength = 289;
		byte[] ikm = CreateData(73, 11);
		byte[] salt = CreateData(37, 29);
		byte[] info = CreateData(infoLength, 47);
		byte[] prk = new byte[HashAlgorithm<Sha256HashAlgorithm>.HashLength];
		HKDF.Extract(HashAlgorithmName.SHA256, ikm, salt, prk);

		byte[] expectedExpanded = new byte[outputLength];
		HKDF.Expand(HashAlgorithmName.SHA256, prk, expectedExpanded, info);
		byte[] expandBuffer = new byte[outputLength];
		info.CopyTo(expandBuffer, 0);
		Hkdf.Expand<Sha256HashAlgorithm>(prk, expandBuffer, expandBuffer.AsSpan().Slice(0, info.Length));
		await Assert.That(expandBuffer).IsEquivalentTo(expectedExpanded, CollectionOrdering.Matching);

		byte[] expectedDerived = new byte[outputLength];
		HKDF.DeriveKey(HashAlgorithmName.SHA256, ikm, expectedDerived, salt, info);
		byte[] deriveBuffer = new byte[outputLength];
		info.CopyTo(deriveBuffer, 0);
		Hkdf.DeriveKey<Sha256HashAlgorithm>(ikm, deriveBuffer, salt, deriveBuffer.AsSpan().Slice(0, info.Length));
		await Assert.That(deriveBuffer).IsEquivalentTo(expectedDerived, CollectionOrdering.Matching);
	}

	[Test]
	public async Task DoesNotModifyInputs()
	{
		byte[] ikm = CreateData(73, 13);
		byte[] salt = CreateData(37, 17);
		byte[] info = CreateData(23, 19);
		byte[] ikmCopy = (byte[])ikm.Clone();
		byte[] saltCopy = (byte[])salt.Clone();
		byte[] infoCopy = (byte[])info.Clone();
		byte[] prk = new byte[HashAlgorithm<Sha256HashAlgorithm>.HashLength];
		byte[] output = new byte[HashAlgorithm<Sha256HashAlgorithm>.HashLength + 11];

		Hkdf.Extract<Sha256HashAlgorithm>(ikm, salt, prk);
		byte[] prkCopy = (byte[])prk.Clone();
		Hkdf.Expand<Sha256HashAlgorithm>(prk, output, info);
		Hkdf.DeriveKey<Sha256HashAlgorithm>(ikm, output, salt, info);

		await Assert.That(ikm).IsEquivalentTo(ikmCopy, CollectionOrdering.Matching);
		await Assert.That(salt).IsEquivalentTo(saltCopy, CollectionOrdering.Matching);
		await Assert.That(info).IsEquivalentTo(infoCopy, CollectionOrdering.Matching);
		await Assert.That(prk).IsEquivalentTo(prkCopy, CollectionOrdering.Matching);
	}

	private static byte[] CreateData(int length, int seed)
	{
		byte[] data = new byte[length];

		for (int i = 0; i < data.Length; ++i)
		{
			data[i] = (byte)(seed + i * 31 + (i >> 1));
		}

		return data;
	}

	private static byte[] CreateOverlapBuffer(ReadOnlySpan<byte> source, int sourceOffset, int destinationOffset, int destinationLength)
	{
		byte[] buffer = new byte[Math.Max(sourceOffset + source.Length, destinationOffset + destinationLength)];
		source.CopyTo(buffer.AsSpan(sourceOffset));
		return buffer;
	}
}
