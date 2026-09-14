using CryptoBase.Abstractions.Hashes;
using CryptoBase.Hashes;
using CryptoBase.Hashes.Sha1;
using CryptoBase.Hashes.Sha224;
using CryptoBase.Hashes.Sha256;
using CryptoBase.Hashes.Sha384;
using CryptoBase.Hashes.Sha512;
using CryptoBase.Hashes.SM3;
using CryptoBase.Kdf;
using System.Security.Cryptography;
using static CryptoBase.Tests.TestUtils;

namespace CryptoBase.Tests.Kdf;

/// <summary>
/// HKDF vectors from RFC 5869, with independently verified SHA-224 and SM3 extensions.
/// </summary>
public class HkdfTest
{
	[Test]
	[Arguments(@"0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b", @"000102030405060708090a0b0c", @"f0f1f2f3f4f5f6f7f8f9", @"077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5", @"3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865")]
	[Arguments(@"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f", @"606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf", @"b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff", @"06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244", @"b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87")]
	[Arguments(@"0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b", @"", @"", @"19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04", @"8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8")]
	public Task Rfc5869Sha256Vectors(string ikmHex, string saltHex, string infoHex, string prkHex, string okmHex)
	{
		return VerifyVector<Sha256HashAlgorithm>(ikmHex, saltHex, infoHex, prkHex, okmHex);
	}

	[Test]
	[Arguments(@"0b0b0b0b0b0b0b0b0b0b0b", @"000102030405060708090a0b0c", @"f0f1f2f3f4f5f6f7f8f9", @"9b6c18c432a7bf8f0e71c8eb88f4b30baa2ba243", @"085a01ea1b10f36933068b56efa5ad81a4f14b822f5b091568a9cdd4f155fda2c22e422478d305f3f896")]
	[Arguments(@"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f", @"606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf", @"b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff", @"8adae09a2a307059478d309b26c4115a224cfaf6", @"0bd770a74d1160f7c9f12cd5912a06ebff6adcae899d92191fe4305673ba2ffe8fa3f1a4e5ad79f3f334b3b202b2173c486ea37ce3d397ed034c7f9dfeb15c5e927336d0441f4c4300e2cff0d0900b52d3b4")]
	[Arguments(@"0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b", @"", @"", @"da8c8a73c7fa77288ec6f5e7c297786aa0d32d01", @"0ac1af7002b3d761d1e55298da9d0506b9ae52057220a306e07b6b87e8df21d0ea00033de03984d34918")]
	[Arguments(@"0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c", @"", @"", @"2adccada18779e7c2077ad2eb19d3f3e731385dd", @"2c91117204d745f3500d636a62f64f0ab3bae548aa53d423b0d1f27ebba6f5e5673a081d70cce7acfc48")]
	public Task Rfc5869Sha1Vectors(string ikmHex, string saltHex, string infoHex, string prkHex, string okmHex)
	{
		return VerifyVector<Sha1HashAlgorithm>(ikmHex, saltHex, infoHex, prkHex, okmHex);
	}

	[Test]
	[Arguments(@"0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b", @"000102030405060708090a0b0c", @"f0f1f2f3f4f5f6f7f8f9", @"e0d6f7b0bd056327b7659f1f39ad850561fbcf4fb10fb58e88eafa55cf7cd01e", @"c69fe91b7aaee2dd5718d72dcaee0cce93f1b8e41f792da51261b6a517e68b36ed2c595572b01dfa359b")]
	public Task SM3Vector(string ikmHex, string saltHex, string infoHex, string prkHex, string okmHex)
	{
		return VerifyVector<SM3HashAlgorithm>(ikmHex, saltHex, infoHex, prkHex, okmHex);
	}

	[Test]
	[Arguments(@"0b2a4a6989a8c8e70726466585a4c4e30322426181a0c0dfff1e3e5d7d9cbcdbfb1a3a597998b8d7f71636557594b4d3f31232517190b0cfef0e2e4d6d8caccbeb0a2a496988a8c7e7", @"1d3c5c7b9bbadaf91938587797b6d6f51534547393b2d2f11130506f8faeceed0d2c4c6b8b", @"2f4e6e8dadccec0b2b4a6a89a9c8e80727466685a5c4e4", @"98b33a183bca36679809f07390e51baddbf14522266a80754089a581", @"3ff9d24f99fab73a1297516d7fe40f884e33b69faf98504b0746328f6331fa434eaed06972b2950b5c4facf667a155732f7d41bb14bcc628795e60a42f4b4c18c05011fc6d5650")]
	public Task Sha224Vector(string ikmHex, string saltHex, string infoHex, string prkHex, string okmHex)
	{
		return VerifyVector<Sha224HashAlgorithm>(ikmHex, saltHex, infoHex, prkHex, okmHex);
	}

	[Test]
	[Arguments(45)]
	[Arguments(103)]
	public Task MatchesPlatformSha384(int outputLength)
	{
		return VerifyAgainstPlatform<Sha384HashAlgorithm>(HashAlgorithmName.SHA384, outputLength);
	}

	[Test]
	[Arguments(61)]
	[Arguments(135)]
	public Task MatchesPlatformSha512(int outputLength)
	{
		return VerifyAgainstPlatform<Sha512HashAlgorithm>(HashAlgorithmName.SHA512, outputLength);
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
	public async Task SupportsMaximumBlockCount()
	{
		byte[] prk = CreateData(HashAlgorithm<Sha256HashAlgorithm>.HashLength, 11);
		byte[] info = CreateData(23, 17);
		byte[] expected = new byte[255 * HashAlgorithm<Sha256HashAlgorithm>.HashLength];
		byte[] actual = new byte[expected.Length];

		HKDF.Expand(HashAlgorithmName.SHA256, prk, expected, info);
		Hkdf.Expand<Sha256HashAlgorithm>(prk, actual, info);

		await Assert.That(actual).IsEquivalentTo(expected, CollectionOrdering.Matching);
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

	private static async Task VerifyVector<THash>(string ikmHex, string saltHex, string infoHex, string prkHex, string okmHex) where THash : unmanaged, IHmacHashCore<THash>
	{
		byte[] ikm = Convert.FromHexString(ikmHex);
		byte[] salt = Convert.FromHexString(saltHex);
		byte[] info = Convert.FromHexString(infoHex);
		byte[] expectedPrk = Convert.FromHexString(prkHex);
		byte[] expectedOkm = Convert.FromHexString(okmHex);
		byte[] prk = new byte[expectedPrk.Length];

		int length = Hkdf.Extract<THash>(ikm, salt, prk);
		await Assert.That(length).IsEqualTo(expectedPrk.Length);
		await Assert.That(prk).IsEquivalentTo(expectedPrk, CollectionOrdering.Matching);

		byte[] expanded = new byte[expectedOkm.Length];
		Hkdf.Expand<THash>(prk, expanded, info);
		await Assert.That(expanded).IsEquivalentTo(expectedOkm, CollectionOrdering.Matching);

		byte[] derived = new byte[expectedOkm.Length];
		Hkdf.DeriveKey<THash>(ikm, derived, salt, info);
		await Assert.That(derived).IsEquivalentTo(expectedOkm, CollectionOrdering.Matching);
	}

	private static async Task VerifyAgainstPlatform<THash>(HashAlgorithmName algorithmName, int outputLength) where THash : unmanaged, IHmacHashCore<THash>
	{
		int hashLength = THash.HashLength;
		byte[] ikm = CreateData(73, 11);
		byte[] salt = CreateData(37, 29);
		byte[] info = CreateData(23, 47);
		byte[] expectedPrk = new byte[hashLength];
		byte[] actualPrk = new byte[hashLength];

		int expectedLength = HKDF.Extract(algorithmName, ikm, salt, expectedPrk);
		int actualLength = Hkdf.Extract<THash>(ikm, salt, actualPrk);
		await Assert.That(actualLength).IsEqualTo(expectedLength);
		await Assert.That(actualPrk).IsEquivalentTo(expectedPrk, CollectionOrdering.Matching);

		byte[] expectedExpanded = new byte[outputLength];
		byte[] actualExpanded = new byte[outputLength];
		HKDF.Expand(algorithmName, expectedPrk, expectedExpanded, info);
		Hkdf.Expand<THash>(actualPrk, actualExpanded, info);
		await Assert.That(actualExpanded).IsEquivalentTo(expectedExpanded, CollectionOrdering.Matching);

		byte[] expectedDerived = new byte[outputLength];
		byte[] actualDerived = new byte[outputLength];
		HKDF.DeriveKey(algorithmName, ikm, expectedDerived, salt, info);
		Hkdf.DeriveKey<THash>(ikm, actualDerived, salt, info);
		await Assert.That(actualDerived).IsEquivalentTo(expectedDerived, CollectionOrdering.Matching);
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
