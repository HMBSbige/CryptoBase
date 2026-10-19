using CryptoBase.IO;
using CryptoBase.Platform;
using CryptoBase.Tests.Macs;
using CryptoBase.Tests.Macs.Hmac;
using CryptoBase.Tests.Wycheproof;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.CompilerServices;
using System.Runtime.Intrinsics.X86;
using System.Security.Cryptography;
using System.Text;
using static CryptoBase.Tests.TestUtils;
using ManagedHmacSha256 = CryptoBase.Macs.Hmac.HmacAlgorithm<CryptoBase.Hashes.Sha256.Sha256HashAlgorithm>;

namespace CryptoBase.Tests.Platform;

[SuppressMessage("ReSharper", "AccessToDisposedClosure")]
public class PlatformHmacSha256Test
{
	// RFC 4231, section 4; test case 5 truncates the output and is left out.
	public static IEnumerable<(string KeyHex, string SourceHex, string ExpectedHex)> Rfc4231Vectors()
	{
		string longKey = string.Concat(Enumerable.Repeat("aa", 131));

		yield return (string.Concat(Enumerable.Repeat("0b", 20)), Hex("Hi There"), @"b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");
		yield return (Hex("Jefe"), Hex("what do ya want for nothing?"), @"5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");
		yield return (string.Concat(Enumerable.Repeat("aa", 20)), string.Concat(Enumerable.Repeat("dd", 50)), @"773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe");
		yield return (@"0102030405060708090a0b0c0d0e0f10111213141516171819", string.Concat(Enumerable.Repeat("cd", 50)), @"82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b");
		yield return (longKey, Hex("Test Using Larger Than Block-Size Key - Hash Key First"), @"60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54");
		yield return
		(
			longKey,
			Hex("This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm."),
			@"9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2"
		);

		static string Hex(string value)
		{
			return Convert.ToHexString(Encoding.ASCII.GetBytes(value));
		}
	}

	[Test]
	[MethodDataSource(nameof(Rfc4231Vectors))]
	public async Task Rfc4231Vector(string keyHex, string sourceHex, string expectedHex)
	{
		await MacAlgorithmTestUtils.VerifyVector<ManagedHmacSha256>(keyHex, sourceHex, expectedHex);
		await MacAlgorithmTestUtils.VerifyVector<PlatformHmacSha256>(keyHex, sourceHex, expectedHex);

		byte[] expected = Convert.FromHexString(expectedHex);
		byte[] destination = new byte[PlatformHmacSha256.MacLength + 1];
		using PlatformHmacSha256 mac = PlatformHmacSha256.Create(Convert.FromHexString(keyHex));
		mac.Append(Convert.FromHexString(sourceHex));
		PrepareDestination(destination);
		int written = mac.GetMacAndReset(destination);
		await AssertOutput(destination, expected, written);
	}

	[Test]
	[MethodDataSource(typeof(WycheproofHmacTest), nameof(WycheproofHmacTest.Vectors), Arguments = ["hmac_sha256_test.json"])]
	public async Task WycheproofVector(MacTestVector vector)
	{
		byte[] mac = new byte[PlatformHmacSha256.MacLength];
		PlatformHmacSha256.Mac(vector.Key, vector.Msg, mac);

		using PlatformHmacSha256 algorithm = PlatformHmacSha256.Create(vector.Key);
		algorithm.Append(vector.Msg);
		byte[] incrementalMac = new byte[PlatformHmacSha256.MacLength];
		algorithm.GetMacAndReset(incrementalMac);

		await Assert.That(incrementalMac).IsEquivalentTo(mac, CollectionOrdering.Matching);
		await Assert.That(mac.AsSpan().StartsWith(vector.Tag)).IsEqualTo(vector.Result is WycheproofResult.Valid);
	}

	[Test]
	public async Task AcceptsEmptyKey()
	{
		const string expectedHex = @"b613679a0814d9ec772f95d778c35fc5ff1697c493715653c6c712144292c5ad";
		await MacAlgorithmTestUtils.VerifyVector<ManagedHmacSha256>(string.Empty, string.Empty, expectedHex);
		await MacAlgorithmTestUtils.VerifyVector<PlatformHmacSha256>(string.Empty, string.Empty, expectedHex);

		byte[] destination = new byte[PlatformHmacSha256.MacLength + 1];
		using PlatformHmacSha256 mac = PlatformHmacSha256.Create(ReadOnlySpan<byte>.Empty);
		PrepareDestination(destination);
		int written = mac.GetMacAndReset(destination);
		await AssertOutput(destination, Convert.FromHexString(expectedHex), written);
	}

	[Test]
	public async Task MatchesManagedAcrossKeyAndMessageLengths()
	{
		byte[] source = CreateDeterministicSource(200);
		byte[] expected = new byte[ManagedHmacSha256.MacLength];
		byte[] destination = new byte[PlatformHmacSha256.MacLength + 1];

		for (int keyLength = 0; keyLength <= 200; ++keyLength)
		{
			byte[] key = CreateDeterministicSource(keyLength);
			using PlatformHmacSha256 mac = PlatformHmacSha256.Create(key);

			foreach (int sourceLength in (int[])[0, 1, keyLength % 67, 63, 64, 65, 200])
			{
				ReadOnlySpan<byte> message = source.AsSpan(0, sourceLength);
				ManagedHmacSha256.Mac(key, message, expected);

				PrepareDestination(destination);
				int written = PlatformHmacSha256.Mac(key, message, destination);
				await AssertOutput(destination, expected, written);

				int split = sourceLength / 3;
				mac.Append(source.AsSpan(0, split));
				mac.Append(source.AsSpan(split, sourceLength - split));
				PrepareDestination(destination);
				written = mac.GetCurrentMac(destination);
				await AssertOutput(destination, expected, written);

				PrepareDestination(destination);
				written = mac.GetMacAndReset(destination);
				await AssertOutput(destination, expected, written);
			}
		}
	}

	[Test]
	public async Task IsPreferredOnlyWithX86ShaExtensions()
	{
		bool expected = X86Base.IsSupported && (X86Base.CpuId(7, 0).Ebx & 1 << 29) is not 0;
		await Assert.That(PlatformHmacSha256.IsPreferred).IsEqualTo(expected);
	}

	[Test]
	public Task LifecycleContract()
	{
		return HmacTest.VerifyLifecycleContract<PlatformHmacSha256>();
	}

	[Test]
	public Task OwnershipContract()
	{
		return HmacTest.VerifyOwnershipContract<PlatformHmacSha256>();
	}

	[Test]
	public Task ShortDestinationsDoNotChangeStateOrOutput()
	{
		return HmacTest.VerifyShortDestinations<PlatformHmacSha256>();
	}

	[Test]
	public async Task PlatformFailureDisposesTheInstance()
	{
		byte[] key = CreateDeterministicSource(32);
		byte[] source = CreateDeterministicSource(19);
		byte[] destination = new byte[PlatformHmacSha256.MacLength];
		Action<PlatformHmacSha256>[] operations =
		[
			mac => mac.Append(source),
			mac => mac.Reset(),
			mac => mac.GetCurrentMac(destination),
			mac => mac.GetMacAndReset(destination),
		];

		foreach (Action<PlatformHmacSha256> operation in operations)
		{
			using IncrementalHash working = IncrementalHash.CreateHMAC(HashAlgorithmName.SHA256, key);
			using PlatformHmacSha256 mac = PlatformHmacSha256.Create(key);

			// Make the next platform call fail.
			PlatformFields.Hmac(mac).Dispose();
			PrepareDestination(destination);
			await Assert.That(() => operation(mac)).ThrowsExactly<ObjectDisposedException>();
			await Assert.That(destination).All(static value => value is DestinationSentinel);

			// Working platform state does not revive the failed instance.
			PlatformFields.Hmac(mac) = working;
			await Assert.That(() => mac.GetMacAndReset(destination)).ThrowsExactly<ObjectDisposedException>();
			await Assert.That(destination).All(static value => value is DestinationSentinel);
		}
	}

	[Test]
	[Arguments(0)]
	[Arguments(20)]
	[Arguments(97)]
	[Arguments(150)]
	public async Task OneShotMacSupportsOverlappingInputsAndDestination(int destinationOffset)
	{
		const int keyOffset = 0;
		const int keyLength = 64;
		const int sourceOffset = 80;
		const int sourceLength = 97;
		int bufferLength = Math.Max(sourceOffset + sourceLength, destinationOffset + PlatformHmacSha256.MacLength);
		byte[] buffer = CreateDeterministicSource(bufferLength);
		byte[] expected = new byte[ManagedHmacSha256.MacLength];
		ManagedHmacSha256.Mac(buffer.AsSpan(keyOffset, keyLength), buffer.AsSpan(sourceOffset, sourceLength), expected);

		int written = PlatformHmacSha256.Mac(buffer.AsSpan(keyOffset, keyLength), buffer.AsSpan(sourceOffset, sourceLength), buffer.AsSpan(destinationOffset, PlatformHmacSha256.MacLength));

		await Assert.That(written).IsEqualTo(PlatformHmacSha256.MacLength);
		await Assert.That(buffer.AsSpan(destinationOffset, written).ToArray()).IsEquivalentTo(expected, CollectionOrdering.Matching);
	}

	[Test]
	public async Task MacStreamAuthenticatesTheBytesWritten()
	{
		byte[] key = CreateDeterministicSource(97);
		byte[] source = CreateDeterministicSource(4099);
		byte[] expected = new byte[ManagedHmacSha256.MacLength];
		ManagedHmacSha256.Mac(key, source, expected);
		using MemoryStream inner = new();
		using MacStream<PlatformHmacSha256> authenticating = MacStream.Create(inner, PlatformHmacSha256.Create(key), true);

		authenticating.Write(source.AsSpan().Slice(0, 1000));
		authenticating.Write(source.AsSpan().Slice(1000));

		byte[] actual = new byte[PlatformHmacSha256.MacLength];
		int written = authenticating.GetMacAndReset(actual);

		using (Assert.Multiple())
		{
			await Assert.That(written).IsEqualTo(expected.Length);
			await Assert.That(actual).IsEquivalentTo(expected, CollectionOrdering.Matching);
			await Assert.That(inner.ToArray()).IsEquivalentTo(source, CollectionOrdering.Matching);
		}
	}

	private static class PlatformFields
	{
		[UnsafeAccessor(UnsafeAccessorKind.Field, Name = "_hmac")]
		public static extern ref IncrementalHash Hmac(PlatformHmacSha256 mac);
	}
}
