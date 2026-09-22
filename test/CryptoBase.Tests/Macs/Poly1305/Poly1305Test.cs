using CryptoBase.Macs.Poly1305;
using System.Numerics;
using System.Text;
using static CryptoBase.Tests.Macs.MacAlgorithmTestUtils;
using static CryptoBase.Tests.TestUtils;

namespace CryptoBase.Tests.Macs.Poly1305;

public class Poly1305Test
{
	private const string Rfc8439LargeMessage =
		"Any submission to the IETF intended by the Contributor for publication " +
		"as all or part of an IETF Internet-Draft or RFC and any statement made " +
		"""within the context of an IETF activity is considered an "IETF Contribution". """ +
		"Such statements include oral statements in IETF sessions, as well as written " +
		"and electronic communications made at any time or place, which are addressed to";

	public static IEnumerable<(int, string)> BackendBoundaryVectors =>
	[
		(63, @"c7bd8c16ddc06f91621b4a9219a0f00a"),
		(64, @"b48e94127ce5d731dd61f838bcd09b65"),
		(65, @"6c8641670c76c181368febfdb34a2b15"),
		(191, @"0531827ed42256ca0e8d4873ec1d7144"),
		(192, @"4e9cb02a2ecf405e75917f84e0e84b16"),
		(193, @"fde8130fafe3b61152eed695d8114b05"),
		(223, @"5c91e71e3ab8c42b0251d8feffd7a996"),
		(224, @"ae050744dedf6c67975c621b888529f1"),
		(225, @"57f7e10ac7389f6b6dd23e4eb8dd3995"),
		(255, @"dfb30ca710ce69f4f996fe4753dd22ae"),
		(256, @"367586a9d819005b023f65ededd14712"),
		(257, @"d7697d238b60fd76fa9b4c7e2fb0eab5"),
		(511, @"88498aa6b85573b5722edeb4a4f3b478"),
		(512, @"8e994f9867944ac0567f3b016591732a"),
		(513, @"5c88b917de123a69b48c697dd2e37417"),
		(1023, @"73c6b8ebce8a0273189f17fccbd7db59"),
		(1024, @"2738ddd040bbc787b9330ac3336f0a65"),
		(1025, @"30c866a40af1119091f11efc25b18341")
	];

	/// <summary>
	/// Includes the RFC 8439 example and independently verified known-answer and block-boundary vectors.
	/// </summary>
	public static IEnumerable<(string, string, string)> Data =>
	[
		(@"85D6BE7857556D337F4452FE42D506A80103808AFB0DB2FD4ABFF6AF4149F51B", @"43727970746F6772617068696320466F72756D2052657365617263682047726F7570", @"a8061dc1305136c6c22b8baf0c0127a9"),
		(@"746869732069732033322d62797465206b657920666f7220506f6c7931333035", @"48656c6c6f20776f726c6421", @"a6f745008f81c916a20dcc74eef2b2f0"),
		(@"746869732069732033322d62797465206b657920666f7220506f6c7931333035", @"85D6BE7857556D337F4452FE42D506A80103808AFB0DB2FD4ABFF6AF4149F51B746869732069732033322d62797465206b657920666f7220506f6c793133303543727970746F6772617068696320466F72756D2052657365617263682047726F75708A438BDEE65C422A8366A2F85E5E93972FF925F667EB483EB01B1CD6C9", @"e147fee9a466f061df416e8e98a39a3f"),
		(@"746869732069732033322d62797465206b657920666f7220506f6c7931333035", @"ec74691700388dace60b6a392f328c2b971b2f952b2a56a5604ac0b66e94bd4ef8a2c3b884cfa59ca342b2e3da53ec1d3b69b62c9a392687aaf55d95a1df6b0ad2c55bb64fc4802cc3feda602b6656a05b40b6e7ad2c55bb64f62882c85b0685353deb7f38cbb1ad69223dcc3457ae5b6b0dfa6bf4ded81d", @"f23f618e65a4179f065e5870d89a1d6b"),
		(@"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", @"", @"101112131415161718191a1b1c1d1e1f"),
		(@"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", @"000102030405060708090a0b0c0d0e", @"5305236ca07fc93d9ca416b23664fa50"),
		(@"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", @"000102030405060708090a0b0c0d0e0f", @"a2291a363def0b53845fa4126a6ad364"),
		(@"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", @"000102030405060708090a0b0c0d0e0f10", @"f735c97f7308fd79222447fe76a96872")
	];

	/// <summary>
	/// RFC 8439, Appendix A.3, test vectors #5-#11.
	/// </summary>
	public static IEnumerable<(string, string, string)> Rfc8439ArithmeticVectors =>
	[
		(@"0200000000000000000000000000000000000000000000000000000000000000", @"ffffffffffffffffffffffffffffffff", @"03000000000000000000000000000000"),
		(@"02000000000000000000000000000000ffffffffffffffffffffffffffffffff", @"02000000000000000000000000000000", @"03000000000000000000000000000000"),
		(@"0100000000000000000000000000000000000000000000000000000000000000", @"fffffffffffffffffffffffffffffffff0ffffffffffffffffffffffffffffff11000000000000000000000000000000", @"05000000000000000000000000000000"),
		(@"0100000000000000000000000000000000000000000000000000000000000000", @"fffffffffffffffffffffffffffffffffbfefefefefefefefefefefefefefefe01010101010101010101010101010101", @"00000000000000000000000000000000"),
		(@"0200000000000000000000000000000000000000000000000000000000000000", @"fdffffffffffffffffffffffffffffff", @"faffffffffffffffffffffffffffffff"),
		(@"0100000000000000040000000000000000000000000000000000000000000000", @"e33594d7505e43b900000000000000003394d7505e4379cd01000000000000000000000000000000000000000000000001000000000000000000000000000000", @"14000000000000005500000000000000"),
		(@"0100000000000000040000000000000000000000000000000000000000000000", @"e33594d7505e43b900000000000000003394d7505e4379cd010000000000000000000000000000000000000000000000", @"13000000000000000000000000000000")
	];

	[Test]
	[MethodDataSource(nameof(Data))]
	public Task OneShotMatchesKnownVectors(string keyHex, string sourceHex, string expectedHex)
	{
		return VerifyVector<Poly1305Algorithm>(keyHex, sourceHex, expectedHex);
	}

	[Test]
	[MethodDataSource(nameof(Rfc8439ArithmeticVectors))]
	public Task Rfc8439ArithmeticBoundaries(string keyHex, string sourceHex, string expectedHex)
	{
		return VerifyVector<Poly1305Algorithm>(keyHex, sourceHex, expectedHex);
	}

	[Test]
	[MethodDataSource(nameof(Rfc8439ArithmeticVectors))]
	public async Task State26MatchesRfc8439ArithmeticBoundaries(string keyHex, string sourceHex, string expectedHex)
	{
		byte[] key = Convert.FromHexString(keyHex);
		byte[] source = Convert.FromHexString(sourceHex);
		byte[] expected = Convert.FromHexString(expectedHex);
		byte[] actual = new byte[Poly1305Algorithm.MacLength];

		ComputeState26Mac(key, source, actual);

		await Assert.That(actual).IsEquivalentTo(expected, CollectionOrdering.Matching);
	}

	[Test]
	public Task Rfc8439LargeVector()
	{
		// RFC 8439, Appendix A.3, Test Vector #3.
		byte[] key = Convert.FromHexString(@"36e5f6b5c5e06070f0efca96227a863e00000000000000000000000000000000");
		byte[] source = Encoding.ASCII.GetBytes(Rfc8439LargeMessage);
		byte[] expected = Convert.FromHexString(@"f3477e7cd95417af89a6b8794c310cf0");

		return VerifyVector<Poly1305Algorithm>(key, source, expected);
	}

	[Test]
	[MethodDataSource(nameof(BackendBoundaryVectors))]
	public Task AutomaticBackendMatchesFixedVectorsAtBoundaries(int length, string expectedHex)
	{
		byte[] key = CreateDeterministicSource(Poly1305Algorithm.KeyLengthInBytes);
		byte[] source = CreateDeterministicSource(length);
		byte[] expected = Convert.FromHexString(expectedHex);

		return VerifyVector<Poly1305Algorithm>(key, source, expected);
	}

	[Test]
	public async Task ShortDestinationDoesNotWrite()
	{
		byte[] key = CreateDeterministicSource(Poly1305Algorithm.KeyLengthInBytes);
		byte[] source = CreateDeterministicSource(73);
		byte[] keyCopy = (byte[])key.Clone();
		byte[] sourceCopy = (byte[])source.Clone();
		byte[] shortDestination = new byte[Poly1305Algorithm.MacLength - 1];
		shortDestination.AsSpan().Fill(DestinationSentinel);

		await Assert.That(() => Poly1305Algorithm.Mac(key, source, shortDestination))
			.ThrowsExactly<ArgumentOutOfRangeException>();

		await Assert.That(shortDestination).All(static value => value is DestinationSentinel);
		await Assert.That(key).IsEquivalentTo(keyCopy, CollectionOrdering.Matching);
		await Assert.That(source).IsEquivalentTo(sourceCopy, CollectionOrdering.Matching);
	}

	[Test]
	[Arguments(Poly1305Algorithm.KeyLengthInBytes - 1)]
	[Arguments(Poly1305Algorithm.KeyLengthInBytes + 1)]
	public async Task InvalidKeysDoNotWrite(int keyLength)
	{
		byte[] source = CreateDeterministicSource(73);
		byte[] invalidKey = new byte[keyLength];
		byte[] destination = new byte[Poly1305Algorithm.MacLength];
		destination.AsSpan().Fill(DestinationSentinel);

		await Assert.That(() => Poly1305Algorithm.Mac(invalidKey, source, destination))
			.ThrowsExactly<ArgumentOutOfRangeException>();

		await Assert.That(destination).All(static value => value is DestinationSentinel);
	}

	private static void ComputeState26Mac(ReadOnlySpan<byte> key, ReadOnlySpan<byte> source, Span<byte> destination)
	{
		Poly1305State26 state = new(key);

		try
		{
			state.Append(source, false);
			state.WriteMac(destination);
		}
		finally
		{
			state.ZeroMemory();
		}
	}

	[Test]
	public async Task SoftwareAndState26MatchIndependentBigIntegerOracle()
	{
		Random random = new(1305);
		int[] lengths = [.. Enumerable.Range(0, 34), 63, 64, 65, 127, 128, 129, 255, 256, 257, 511, 512, 513, 1024, 4097];
		BigInteger prime = (BigInteger.One << 130) - 5;
		BigInteger tagMask = (BigInteger.One << 128) - 1;
		BigInteger keyMask = new(Convert.FromHexString("FFFFFF0FFCFFFF0FFCFFFF0FFCFFFF0F"), isUnsigned: true);

		for (int trial = 0; trial < 8; ++trial)
		{
			byte[] key = new byte[32];
			random.NextBytes(key);

			if (trial is 0)
			{
				Array.Fill(key, byte.MaxValue);
			}

			BigInteger r = new BigInteger(key.AsSpan(0, 16), isUnsigned: true) & keyMask;
			BigInteger pad = new(key.AsSpan(16), isUnsigned: true);

			foreach (int length in lengths)
			{
				byte[] source = new byte[length];
				random.NextBytes(source);
				BigInteger accumulator = BigInteger.Zero;

				for (int offset = 0; offset < length; offset += 16)
				{
					int blockLength = Math.Min(16, length - offset);
					BigInteger block = new BigInteger(source.AsSpan(offset, blockLength), isUnsigned: true) + (BigInteger.One << blockLength * 8);
					accumulator = (accumulator + block) * r % prime;
				}

				byte[] expected = new byte[16];
				bool written = (accumulator + pad & tagMask).TryWriteBytes(expected, out _, isUnsigned: true);
				await Assert.That(written).IsTrue();
				byte[] actual = new byte[16];
				ComputeSoftwareMac(key, source, actual);
				await Assert.That(actual).IsEquivalentTo(expected, CollectionOrdering.Matching);
				ComputeState26Mac(key, source, actual);
				await Assert.That(actual).IsEquivalentTo(expected, CollectionOrdering.Matching);
			}
		}

		return;

		static void ComputeSoftwareMac(ReadOnlySpan<byte> key, ReadOnlySpan<byte> source, Span<byte> destination)
		{
			Poly1305Software state = default;
			Poly1305Software.Initialize(ref state, key);

			try
			{
				state.AppendMessage(source);
				state.WriteMac(destination);
			}
			finally
			{
				state.ZeroMemory();
			}
		}
	}
}
