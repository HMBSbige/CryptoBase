using CryptoBase.Abstractions.Hashes;
using CryptoBase.Hashes;
using CryptoBase.Hashes.Blake2b;
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

public class HkdfTest
{
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
	[Arguments(@"0b2a4a6989a8c8e70726466585a4c4e30322426181a0c0dfff1e3e5d7d9cbcdbfb1a3a597998b8d7f71636557594b4d3f31232517190b0cfef0e2e4d6d8caccbeb0a2a496988a8c7e7", @"1d3c5c7b9bbadaf91938587797b6d6f51534547393b2d2f11130506f8faeceed0d2c4c6b8b", @"2f4e6e8dadccec0b2b4a6a89a9c8e80727466685a5c4e4", @"2b3167b61c2c606180e8947b96107fd31143a6c354eec35ee8640918b20b08899951e78c3bb259e5a0c79626bce54572401a38ebb258397aca668786bbcecba7", @"df54b7b5138a5222c48d31d68474b928f3d0a6f2a2effb446d840f14933064ea11d1407f75379f0ab0c9c51f069ba1762c13de29b3cef2fe928f2bd422f158d2")]
	[Arguments(@"0b2a4a6989a8c8e70726466585a4c4e30322426181a0c0dfff1e3e5d7d9cbcdbfb1a3a597998b8d7f71636557594b4d3f31232517190b0cfef0e2e4d6d8caccbeb0a2a496988a8c7e70626456584a4c3", @"1d3c5c7b9bbadaf91938587797b6d6f51534547393b2d2f11130506f8faeceed0d2c4c6b8baacae90928486787a6c6e50524446383a2c2e10120405f7f9ebeddfd1c3c5b7b9abad9f91838577796b6d5f51434537392b2d1f110304f6f8eaecded0c2c4b6b8aaac9e90828476786a6c5e50424436382a2c1e100203f5f7e9ebddd", @"2f4e6e8dadccec0b2b4a6a89a9c8e80727466685a5c4e40323426281a1c0e0ff1f3e5e7d9dbcdcfb1b3a5a7999b8d8f71736567595b4d4f31332527191b0d0ef0f2e4e6d8daccceb0b2a4a6989a8c8e70726466585a4c4e30322426181a0c0dfff1e3e5d7d9cbcdbfb1a3a597998b8d7f71636557594b4d3f31232517190b0cfef0e2e4d6d8caccbeb0a2a496988a8c7e70626456584a4c3e30222416180a0bfdffe1e3d5d7c9cbbdbfa1a39597898b7d7f61635557494b3d3f21231517090afcfee0e2d4d6c8cab", @"ec46462f658682c8964e790c84ced05a8f4c4ed0ee61c360e0ff84370283ff3e79e2d1cf591ec81d384f969bc11eb73c8e1c7950f26dd19facc7de5b4a2f15ec", @"d8f7136be4cf92a82fcd5517df19979e4e0f2e9bd92fb33e6aeb14849836256ead131406d94975d0e7c8e226c849ceefadb2cd354b62efb5b8d693711068599153d4d313678bdd437435401f8bc94b6bae23303d152f496c02a3a033c372c8e2200e9735493cca7e594eea022da844a3f4924977fb8ebc1d9c6be143756c47b0e565")]
	public Task Blake2b512Vector(string ikmHex, string saltHex, string infoHex, string prkHex, string okmHex)
	{
		return VerifyVector<Blake2b512HashAlgorithm>(ikmHex, saltHex, infoHex, prkHex, okmHex);
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
