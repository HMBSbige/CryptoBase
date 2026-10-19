using CryptoBase.Abstractions.Macs;
using CryptoBase.Hashes.Sha256;
using CryptoBase.Kdf;
using CryptoBase.Macs.Hmac;
using CryptoBase.Platform;
using CryptoBase.Tests.Wycheproof;
using static CryptoBase.Tests.Kdf.HkdfTest;
using static CryptoBase.Tests.TestUtils;

namespace CryptoBase.Tests.Kdf;

[GenerateGenericTest(typeof(PlatformHmacSha256))]
[GenerateGenericTest(typeof(HmacAlgorithm<Sha256HashAlgorithm>))]
[GenerateGenericTest(typeof(ClobberingHmacSha256))]
public class HkdfGenericTest<TMac> where TMac : class, IMacAlgorithm<TMac>
{
	private const int MacLength = 32;

	// RFC 5869, appendix A, test cases 1 to 3
	public static IEnumerable<(string IkmHex, string SaltHex, string InfoHex, string PrkHex, string OkmHex)> Rfc5869Vectors()
	{
		yield return
		(
			string.Concat(Enumerable.Repeat("0b", 22)),
			@"000102030405060708090a0b0c",
			@"f0f1f2f3f4f5f6f7f8f9",
			@"077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5",
			@"3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
		);
		yield return
		(
			RangeHex(0x00, 80),
			RangeHex(0x60, 80),
			RangeHex(0xb0, 80),
			@"06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244",
			@"b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87"
		);
		yield return
		(
			string.Concat(Enumerable.Repeat("0b", 22)),
			string.Empty,
			string.Empty,
			@"19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04",
			@"8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8"
		);

		static string RangeHex(int start, int count)
		{
			return Convert.ToHexString(Enumerable.Range(start, count).Select(static value => (byte)value).ToArray());
		}
	}

	[Test]
	[MethodDataSource(nameof(Rfc5869Vectors))]
	public async Task Rfc5869Vector(string ikmHex, string saltHex, string infoHex, string prkHex, string okmHex)
	{
		byte[] ikm = Convert.FromHexString(ikmHex);
		byte[] salt = Convert.FromHexString(saltHex);
		byte[] info = Convert.FromHexString(infoHex);
		byte[] expectedPrk = Convert.FromHexString(prkHex);
		byte[] expectedOkm = Convert.FromHexString(okmHex);

		byte[] prk = new byte[MacLength + 1];
		PrepareDestination(prk);
		int written = Hkdf<TMac>.Extract(ikm, salt, prk);
		await AssertOutput(prk, expectedPrk, written);

		byte[] expanded = CreateGuardedBuffer(3, expectedOkm.Length);
		Hkdf<TMac>.Expand(expectedPrk, expanded.AsSpan(3, expectedOkm.Length), info);
		await AssertOutput(expanded, 3, expectedOkm);

		byte[] derived = CreateGuardedBuffer(3, expectedOkm.Length);
		Hkdf<TMac>.DeriveKey(ikm, derived.AsSpan(3, expectedOkm.Length), salt, info);
		await AssertOutput(derived, 3, expectedOkm);
	}

	[Test]
	[MethodDataSource(typeof(WycheproofHkdfTest), nameof(WycheproofHkdfTest.Vectors), Arguments = ["hkdf_sha256_test.json"])]
	public async Task WycheproofVector(HkdfTestVector vector)
	{
		byte[] prk = new byte[MacLength];
		Hkdf<TMac>.Extract(vector.Ikm, vector.Salt, prk);
		byte[] expanded = new byte[vector.Size];
		byte[] derived = new byte[vector.Size];

		if (vector.Result is WycheproofResult.Invalid)
		{
			// The invalid vectors request more than 255 output blocks.
			await Assert.That(() => Hkdf<TMac>.Expand(prk, expanded, vector.Info)).ThrowsExactly<ArgumentOutOfRangeException>().WithParameterName("output");
			await Assert.That(() => Hkdf<TMac>.DeriveKey(vector.Ikm, derived, vector.Salt, vector.Info)).ThrowsExactly<ArgumentOutOfRangeException>().WithParameterName("output");
			return;
		}

		Hkdf<TMac>.Expand(prk, expanded, vector.Info);
		Hkdf<TMac>.DeriveKey(vector.Ikm, derived, vector.Salt, vector.Info);
		await Assert.That(expanded).IsEquivalentTo(vector.Okm, CollectionOrdering.Matching);
		await Assert.That(derived).IsEquivalentTo(vector.Okm, CollectionOrdering.Matching);
	}

	[Test]
	[Arguments(0)]
	[Arguments(1)]
	[Arguments(31)]
	[Arguments(32)]
	[Arguments(33)]
	[Arguments(300)]
	public async Task MatchesNonGenericHkdf(int infoLength)
	{
		await Assert.That(TMac.MacLength).IsEqualTo(MacLength);

		byte[] ikm = CreateData(73, 11);
		byte[] salt = CreateData(37, 29);
		byte[] info = CreateData(infoLength, 47);
		byte[] expectedPrk = new byte[MacLength];
		byte[] prk = new byte[MacLength];
		Hkdf.Extract<Sha256HashAlgorithm>(ikm, salt, expectedPrk);
		int written = Hkdf<TMac>.Extract(ikm, salt, prk);
		await Assert.That(written).IsEqualTo(MacLength);
		await Assert.That(prk).IsEquivalentTo(expectedPrk, CollectionOrdering.Matching);

		byte[] longPrk = CreateData(300, 13);

		foreach (int outputLength in (int[])[1, 31, 32, 33, 63, 64, 65, 1000, 255 * MacLength])
		{
			byte[] expected = new byte[outputLength];
			byte[] actual = new byte[outputLength];

			Hkdf.Expand<Sha256HashAlgorithm>(prk, expected, info);
			Hkdf<TMac>.Expand(prk, actual, info);
			await Assert.That(actual).IsEquivalentTo(expected, CollectionOrdering.Matching);

			Hkdf.Expand<Sha256HashAlgorithm>(longPrk, expected, info);
			Hkdf<TMac>.Expand(longPrk, actual, info);
			await Assert.That(actual).IsEquivalentTo(expected, CollectionOrdering.Matching);

			Hkdf.DeriveKey<Sha256HashAlgorithm>(ikm, expected, salt, info);
			Hkdf<TMac>.DeriveKey(ikm, actual, salt, info);
			await Assert.That(actual).IsEquivalentTo(expected, CollectionOrdering.Matching);
		}
	}

	[Test]
	public async Task RejectsInvalidLengthsWithoutWriting()
	{
		byte[] ikm = CreateData(37, 3);
		byte[] salt = CreateData(19, 5);
		byte[] info = CreateData(11, 7);
		byte[] prk = new byte[MacLength];
		byte[] shortPrk = new byte[MacLength - 1];
		PrepareDestination(shortPrk);
		byte[] maximumOutput = new byte[255 * MacLength];
		byte[] oversizedOutput = new byte[255 * MacLength + 1];
		PrepareDestination(oversizedOutput);

		await Assert.That(() => Hkdf<TMac>.Extract(ikm, salt, shortPrk)).ThrowsExactly<ArgumentOutOfRangeException>().WithParameterName("prk");
		await Assert.That(shortPrk).All(static value => value is DestinationSentinel);

		await Assert.That(() => Hkdf<TMac>.Expand(prk, Array.Empty<byte>(), info)).ThrowsExactly<ArgumentOutOfRangeException>().WithParameterName("output");

		byte[] output = [DestinationSentinel];
		await Assert.That(() => Hkdf<TMac>.Expand(shortPrk, output, info)).ThrowsExactly<ArgumentOutOfRangeException>().WithParameterName("prk");
		await Assert.That(output[0]).IsEqualTo(DestinationSentinel);

		await Assert.That(() => Hkdf<TMac>.Expand(prk, oversizedOutput, info)).ThrowsExactly<ArgumentOutOfRangeException>().WithParameterName("output");
		await Assert.That(oversizedOutput).All(static value => value is DestinationSentinel);

		await Assert.That(() => Hkdf<TMac>.DeriveKey(ikm, Array.Empty<byte>(), salt, info)).ThrowsExactly<ArgumentOutOfRangeException>().WithParameterName("output");

		await Assert.That(() => Hkdf<TMac>.DeriveKey(ikm, oversizedOutput, salt, info)).ThrowsExactly<ArgumentOutOfRangeException>().WithParameterName("output");
		await Assert.That(oversizedOutput).All(static value => value is DestinationSentinel);

		byte[] expected = new byte[maximumOutput.Length];
		Hkdf.Expand<Sha256HashAlgorithm>(prk, expected, info);
		Hkdf<TMac>.Expand(prk, maximumOutput, info);
		await Assert.That(maximumOutput).IsEquivalentTo(expected, CollectionOrdering.Matching);
	}

	[Test]
	[MatrixDataSource]
	public async Task SupportsPrkAndOutputOverlap([Matrix(32, 300)] int prkLength, [Matrix(20, 32, 73, 400)] int outputLength, [Matrix(0, 10)] int prkOffset, [Matrix(0, 10)] int outputOffset)
	{
		byte[] prk = CreateData(prkLength, 13);
		byte[] info = CreateData(23, 19);
		byte[] expected = new byte[outputLength];
		Hkdf.Expand<Sha256HashAlgorithm>(prk, expected, info);

		byte[] buffer = CreateOverlapBuffer(prk, prkOffset, outputOffset, outputLength);
		Hkdf<TMac>.Expand(buffer.AsSpan(prkOffset, prk.Length), buffer.AsSpan(outputOffset, outputLength), info);

		await Assert.That(buffer.AsMemory(outputOffset, outputLength)).IsEquivalentTo(expected, CollectionOrdering.Matching);
	}

	[Test]
	[Arguments(0, 0)]
	[Arguments(0, 10)]
	[Arguments(10, 0)]
	public async Task SupportsIkmAndPrkOverlap(int ikmOffset, int prkOffset)
	{
		byte[] ikm = CreateData(73, 11);
		byte[] salt = CreateData(37, 29);
		byte[] expected = new byte[MacLength];
		Hkdf.Extract<Sha256HashAlgorithm>(ikm, salt, expected);

		byte[] buffer = CreateOverlapBuffer(ikm, ikmOffset, prkOffset, MacLength);
		int written = Hkdf<TMac>.Extract(buffer.AsSpan(ikmOffset, ikm.Length), salt, buffer.AsSpan(prkOffset, MacLength));

		await Assert.That(written).IsEqualTo(MacLength);
		await Assert.That(buffer.AsMemory(prkOffset, MacLength)).IsEquivalentTo(expected, CollectionOrdering.Matching);
	}

	[Test]
	[Arguments(0, 0)]
	[Arguments(0, 10)]
	[Arguments(10, 0)]
	public async Task SupportsSaltAndPrkOverlap(int saltOffset, int prkOffset)
	{
		byte[] ikm = CreateData(73, 11);
		byte[] salt = CreateData(37, 29);
		byte[] expected = new byte[MacLength];
		Hkdf.Extract<Sha256HashAlgorithm>(ikm, salt, expected);

		byte[] buffer = CreateOverlapBuffer(salt, saltOffset, prkOffset, MacLength);
		int written = Hkdf<TMac>.Extract(ikm, buffer.AsSpan(saltOffset, salt.Length), buffer.AsSpan(prkOffset, MacLength));

		await Assert.That(written).IsEqualTo(MacLength);
		await Assert.That(buffer.AsMemory(prkOffset, MacLength)).IsEquivalentTo(expected, CollectionOrdering.Matching);
	}

	[Test]
	[MatrixDataSource]
	public async Task SupportsInfoAndOutputOverlap([Matrix(20, 32, 64, 97)] int outputLength, [Matrix(0, 10)] int infoOffset, [Matrix(0, 10)] int outputOffset)
	{
		byte[] ikm = CreateData(73, 11);
		byte[] salt = CreateData(37, 29);
		byte[] prk = CreateData(MacLength, 13);
		byte[] info = CreateData(257, 19);

		byte[] expected = new byte[outputLength];
		Hkdf.Expand<Sha256HashAlgorithm>(prk, expected, info);
		byte[] buffer = CreateOverlapBuffer(info, infoOffset, outputOffset, outputLength);
		Hkdf<TMac>.Expand(prk, buffer.AsSpan(outputOffset, outputLength), buffer.AsSpan(infoOffset, info.Length));
		await Assert.That(buffer.AsMemory(outputOffset, outputLength)).IsEquivalentTo(expected, CollectionOrdering.Matching);

		Hkdf.DeriveKey<Sha256HashAlgorithm>(ikm, expected, salt, info);
		buffer = CreateOverlapBuffer(info, infoOffset, outputOffset, outputLength);
		Hkdf<TMac>.DeriveKey(ikm, buffer.AsSpan(outputOffset, outputLength), salt, buffer.AsSpan(infoOffset, info.Length));
		await Assert.That(buffer.AsMemory(outputOffset, outputLength)).IsEquivalentTo(expected, CollectionOrdering.Matching);
	}

	[Test]
	[Arguments(0, 0)]
	[Arguments(0, 10)]
	[Arguments(10, 0)]
	public async Task SupportsIkmAndSaltAndOutputOverlapInDeriveKey(int inputOffset, int outputOffset)
	{
		const int outputLength = 97;
		byte[] ikm = CreateData(73, 11);
		byte[] salt = CreateData(37, 29);
		byte[] info = CreateData(23, 47);
		byte[] expected = new byte[outputLength];
		Hkdf.DeriveKey<Sha256HashAlgorithm>(ikm, expected, salt, info);

		byte[] buffer = CreateOverlapBuffer(ikm, inputOffset, outputOffset, outputLength);
		Hkdf<TMac>.DeriveKey(buffer.AsSpan(inputOffset, ikm.Length), buffer.AsSpan(outputOffset, outputLength), salt, info);
		await Assert.That(buffer.AsMemory(outputOffset, outputLength)).IsEquivalentTo(expected, CollectionOrdering.Matching);

		buffer = CreateOverlapBuffer(salt, inputOffset, outputOffset, outputLength);
		Hkdf<TMac>.DeriveKey(ikm, buffer.AsSpan(outputOffset, outputLength), buffer.AsSpan(inputOffset, salt.Length), info);
		await Assert.That(buffer.AsMemory(outputOffset, outputLength)).IsEquivalentTo(expected, CollectionOrdering.Matching);
	}

	[Test]
	public async Task SupportsExactInfoAndOutputOverlap()
	{
		const int outputLength = 289;
		byte[] ikm = CreateData(73, 11);
		byte[] salt = CreateData(37, 29);
		byte[] info = CreateData(257, 47);
		byte[] prk = new byte[MacLength];
		Hkdf.Extract<Sha256HashAlgorithm>(ikm, salt, prk);

		byte[] expectedExpanded = new byte[outputLength];
		Hkdf.Expand<Sha256HashAlgorithm>(prk, expectedExpanded, info);
		byte[] expandBuffer = new byte[outputLength];
		info.CopyTo(expandBuffer, 0);
		Hkdf<TMac>.Expand(prk, expandBuffer, expandBuffer.AsSpan().Slice(0, info.Length));
		await Assert.That(expandBuffer).IsEquivalentTo(expectedExpanded, CollectionOrdering.Matching);

		byte[] expectedDerived = new byte[outputLength];
		Hkdf.DeriveKey<Sha256HashAlgorithm>(ikm, expectedDerived, salt, info);
		byte[] deriveBuffer = new byte[outputLength];
		info.CopyTo(deriveBuffer, 0);
		Hkdf<TMac>.DeriveKey(ikm, deriveBuffer, salt, deriveBuffer.AsSpan().Slice(0, info.Length));
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
		byte[] prk = new byte[MacLength];
		byte[] output = new byte[MacLength + 11];

		Hkdf<TMac>.Extract(ikm, salt, prk);
		byte[] prkCopy = (byte[])prk.Clone();
		Hkdf<TMac>.Expand(prk, output, info);
		Hkdf<TMac>.DeriveKey(ikm, output, salt, info);

		await Assert.That(ikm).IsEquivalentTo(ikmCopy, CollectionOrdering.Matching);
		await Assert.That(salt).IsEquivalentTo(saltCopy, CollectionOrdering.Matching);
		await Assert.That(info).IsEquivalentTo(infoCopy, CollectionOrdering.Matching);
		await Assert.That(prk).IsEquivalentTo(prkCopy, CollectionOrdering.Matching);
	}
}
