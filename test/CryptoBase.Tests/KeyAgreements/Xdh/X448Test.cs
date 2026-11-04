using CryptoBase.KeyAgreements.Xdh;
using System.Numerics;
using System.Reflection;
using System.Runtime.InteropServices;
using static CryptoBase.Tests.EllipticCurves.Curve448.Curve448Reference;
using static CryptoBase.Tests.KeyAgreements.KeyAgreementTestUtils;
using static CryptoBase.Tests.KeyAgreements.Xdh.X448TestUtils;
using static CryptoBase.Tests.TestUtils;

namespace CryptoBase.Tests.KeyAgreements.Xdh;

public class X448Test
{
	private const int Iterations = 6;

	private static readonly byte[] Five = EncodeInteger(5);

	[Test]
	public async Task LengthsAreFixed()
	{
		await Assert.That((X448.PrivateKeyLength, X448.PublicKeyLength, X448.SharedSecretLength)).IsEqualTo((56, 56, 56));
	}

	[Test]
	public async Task AnyPrivateKeyRoundTripsAndClampsWhenUsed()
	{
		Random random = new(1);
		List<byte[]> privateKeys = [new byte[56], Enumerable.Repeat((byte)0xFF, 56).ToArray(), Five];

		for (int i = 0; i < Iterations; ++i)
		{
			privateKeys.Add(RandomBytes(random));
		}

		List<string> failures = [];

		foreach (byte[] privateKey in privateKeys)
		{
			using X448 key = X448.ImportPrivateKey(privateKey);
			byte[] flipped = (byte[])privateKey.Clone();
			flipped[0] ^= 0x03;
			flipped[55] ^= 0x80;
			using X448 clampedAlike = X448.ImportPrivateKey(flipped);
			byte[] publicKey = ExportPublicKey(key);

			if (!ExportPrivateKey(key).AsSpan().SequenceEqual(privateKey) || !publicKey.AsSpan().SequenceEqual(X448Function(privateKey, Five)) || !ExportPublicKey(clampedAlike).AsSpan().SequenceEqual(publicKey))
			{
				failures.Add($"private key {Convert.ToHexString(privateKey)}");
			}
		}

		await Assert.That(failures).IsEmpty();
	}

	// u ≥ p is reduced.
	[Test]
	public async Task SharedSecretsMatchTheReference()
	{
		Random random = new(2);
		List<byte[]> peers = [EncodeInteger(P + 2), EncodeInteger((BigInteger.One << 448) - 1), EncodeInteger(P + (BigInteger.One << 223)), Five];

		for (int i = 0; i < 2 * Iterations; ++i)
		{
			peers.Add(RandomBytes(random));
		}

		List<string> failures = [];
		int twist = 0;

		foreach (byte[] peer in peers)
		{
			byte[] privateKey = RandomBytes(random);
			using X448 key = X448.ImportPrivateKey(privateKey);
			BigInteger u = DecodeInteger(peer);
			twist += IsSquare(u * u * u + 156326 * u * u + u) ? 0 : 1;

			if (!DeriveSharedSecret(key, peer).AsSpan().SequenceEqual(X448Function(privateKey, peer)))
			{
				failures.Add($"peer {Convert.ToHexString(peer)}");
			}
		}

		using (Assert.Multiple())
		{
			await Assert.That(failures).IsEmpty();
			await Assert.That(twist).IsPositive();
		}
	}

	// The reference gives 0 for these with any key.
	[Test]
	public async Task SmallOrderPublicKeysReturnFalse()
	{
		Random random = new(3);
		byte[][] smallOrder = SmallOrderPublicKeys();
		List<byte[]> privateKeys = [new byte[56], Enumerable.Repeat((byte)0xFF, 56).ToArray(), RandomBytes(random), RandomBytes(random)];
		List<string> failures = [];

		foreach (byte[] privateKey in privateKeys)
		{
			using X448 key = X448.ImportPrivateKey(privateKey);

			foreach (byte[] peer in smallOrder)
			{
				(bool result, byte[] output) = TryDeriveSharedSecret(key, peer);

				if (result || output.AsSpan().ContainsAnyExcept(DestinationSentinel) || X448Function(privateKey, peer).AsSpan().ContainsAnyExcept((byte)0))
				{
					failures.Add($"private key {Convert.ToHexString(privateKey)}, peer {Convert.ToHexString(peer)}");
				}
			}
		}

		await Assert.That(failures).IsEmpty();
	}

	// 4L survives clamping: its secret is 0 with every point of the curve but not of the twist.
	[Test]
	public async Task TheClampedMultipleOfTheOrderFollowsTheFunction()
	{
		byte[] privateKey = EncodeInteger(4 * L);
		using X448 key = X448.ImportPrivateKey(privateKey);
		using X448 peer = X448.GenerateKey();
		byte[] twistPoint = EncodeInteger(6);
		(bool curveResult, byte[] curveOutput) = TryDeriveSharedSecret(key, ExportPublicKey(peer));

		using (Assert.Multiple())
		{
			await Assert.That(DecodeScalar(privateKey)).IsEqualTo(4 * L);
			await Assert.That(ExportPublicKey(key)).IsEquivalentTo(new byte[56], CollectionOrdering.Matching);
			await Assert.That(curveResult).IsFalse();
			await Assert.That(curveOutput).All(static value => value is DestinationSentinel);
			await Assert.That(IsSquare(216 + 156326 * 36 + 6)).IsFalse();
			await Assert.That(DeriveSharedSecret(key, twistPoint)).IsEquivalentTo(X448Function(privateKey, twistPoint), CollectionOrdering.Matching);
		}
	}

	[Test]
	public async Task KeyOperationsDoNotAllocate()
	{
		// Without optimization, every read of a constant ReadOnlySpan<ulong> allocates a field handle.
		SkipUnlessOptimized<X448>();

		using X448 key = X448.GenerateKey();
		using X448 peer = X448.GenerateKey();
		byte[] privateKey = new byte[X448.PrivateKeyLength];
		byte[] publicKey = new byte[X448.PublicKeyLength];
		byte[] peerPublicKey = ExportPublicKey(peer);
		byte[] invalidPublicKey = new byte[X448.PublicKeyLength];
		byte[] sharedSecret = new byte[X448.SharedSecretLength];

		bool results = Exercise(key, privateKey, publicKey, peerPublicKey, invalidPublicKey, sharedSecret);
		long before = GC.GetAllocatedBytesForCurrentThread();
		results &= Exercise(key, privateKey, publicKey, peerPublicKey, invalidPublicKey, sharedSecret);
		long allocated = GC.GetAllocatedBytesForCurrentThread() - before;

		using (Assert.Multiple())
		{
			await Assert.That(allocated).IsZero();
			await Assert.That(results).IsTrue();
			await Assert.That(sharedSecret).IsEquivalentTo(DeriveSharedSecret(peer, publicKey), CollectionOrdering.Matching);
		}
	}

	[Test]
	public async Task DisposeErasesTheKey()
	{
		X448 key = X448.ImportPrivateKey(Enumerable.Repeat((byte)0xA7, 56).ToArray());
		byte[] before = KeyContents(key);
		key.Dispose();
		byte[] after = KeyContents(key);

		using (Assert.Multiple())
		{
			await Assert.That(before.AsSpan().ContainsAnyExcept((byte)0)).IsTrue();
			await Assert.That(after.AsSpan().ContainsAnyExcept((byte)0)).IsFalse();
		}
	}

	private static bool Exercise(X448 key, byte[] privateKey, byte[] publicKey, byte[] peerPublicKey, byte[] invalidPublicKey, byte[] sharedSecret)
	{
		key.ExportPrivateKey(privateKey);
		key.ExportPublicKey(publicKey);
		bool rejected = !key.TryDeriveSharedSecret(invalidPublicKey, sharedSecret);
		return key.TryDeriveSharedSecret(peerPublicKey, sharedSecret) & rejected;
	}

	private static byte[] RandomBytes(Random random)
	{
		byte[] bytes = new byte[56];
		random.NextBytes(bytes);
		return bytes;
	}

	private static byte[] KeyContents(X448 key)
	{
		object holder = typeof(X448).GetField("_key", BindingFlags.Instance | BindingFlags.NonPublic)?.GetValue(key) ?? throw new InvalidOperationException("X448 has no key field.");
		X448Key copy = (X448Key)holder;
		return MemoryMarshal.AsBytes(new ReadOnlySpan<X448Key>(in copy)).ToArray();
	}
}
