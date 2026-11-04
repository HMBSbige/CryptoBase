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

	// The clamped 4L fails even with a twist point, whose shared secret is not 0.
	[Test]
	public async Task OneInversionGivesBothEphemeralResults()
	{
		Random random = new(5);
		List<string> failures = [];

		for (int i = 0; i < 2 * Iterations; ++i)
		{
			byte[] privateKey = i is 0 ? Enumerable.Repeat((byte)0xFF, 56).ToArray() : RandomBytes(random);
			byte[] peer = i switch
			{
				0 => Five,
				1 => EncodeInteger(6),
				2 => EncodeInteger(P + 2),
				3 => EncodeInteger(P + 6),
				_ => RandomBytes(random)
			};
			byte[] publicKey = new byte[X448.PublicKeyLength];
			byte[] sharedSecret = new byte[X448.SharedSecretLength];
			byte[] separateSecret = new byte[X448.SharedSecretLength];
			bool derived = X448Key.TryDerivePublicKeyAndSharedSecret(privateKey, peer, publicKey, sharedSecret);
			bool separate = X448Key.TryDeriveSharedSecret(privateKey, peer, separateSecret);

			if (!derived || !separate || !publicKey.AsSpan().SequenceEqual(X448Function(privateKey, Five)) || !sharedSecret.AsSpan().SequenceEqual(separateSecret))
			{
				failures.Add($"private key {Convert.ToHexString(privateKey)}, peer {Convert.ToHexString(peer)}");
			}
		}

		byte[] multiple = EncodeInteger(4 * L);
		byte[] twistPoint = EncodeInteger(6);
		byte[] untouchedPublicKey = CreateGuardedBuffer(0, X448.PublicKeyLength, 0);
		byte[] untouchedSecret = CreateGuardedBuffer(0, X448.SharedSecretLength, 0);
		bool derivedForMultiple = X448Key.TryDerivePublicKeyAndSharedSecret(multiple, twistPoint, untouchedPublicKey, untouchedSecret);

		using (Assert.Multiple())
		{
			await Assert.That(failures).IsEmpty();
			await Assert.That(X448Function(multiple, twistPoint).AsSpan().ContainsAnyExcept((byte)0)).IsTrue();
			await Assert.That(derivedForMultiple).IsFalse();
			await Assert.That(untouchedPublicKey).All(static value => value is DestinationSentinel);
			await Assert.That(untouchedSecret).All(static value => value is DestinationSentinel);
		}
	}

	// The ephemeral one fails for the clamped 4L, the static one for a peer of small order, whatever the sender's key.
	[Test]
	public async Task OneInversionGivesTheAuthenticatedResults()
	{
		Random random = new(6);
		List<string> failures = [];

		for (int i = 0; i < 2 * Iterations; ++i)
		{
			byte[] privateKey = RandomBytes(random);
			byte[] senderPrivateKey = RandomBytes(random);
			byte[] peer = i switch
			{
				0 => Five,
				1 => EncodeInteger(6),
				2 => EncodeInteger(P + 2),
				3 => EncodeInteger(P + 6),
				_ => RandomBytes(random)
			};
			byte[] sender = i switch
			{
				2 => EncodeInteger(6),
				3 => EncodeInteger(P + 2),
				4 => EncodeInteger((BigInteger.One << 448) - 1),
				_ => RandomBytes(random)
			};
			byte[] publicKey = new byte[X448.PublicKeyLength];
			byte[] sharedSecrets = new byte[2 * X448.SharedSecretLength];
			byte[] staticSecrets = new byte[2 * X448.SharedSecretLength];
			bool derived = X448Key.TryDerivePublicKeyAndSharedSecrets(privateKey, senderPrivateKey, peer, publicKey, sharedSecrets);
			bool derivedStatic = X448Key.TryDeriveSharedSecrets(privateKey, peer, sender, staticSecrets);
			byte[] expected = [.. X448Function(privateKey, peer), .. X448Function(senderPrivateKey, peer)];
			byte[] expectedStatic = [.. X448Function(privateKey, peer), .. X448Function(privateKey, sender)];

			if (!derived || !derivedStatic || !publicKey.AsSpan().SequenceEqual(X448Function(privateKey, Five)) || !sharedSecrets.AsSpan().SequenceEqual(expected) || !staticSecrets.AsSpan().SequenceEqual(expectedStatic))
			{
				failures.Add($"private key {Convert.ToHexString(privateKey)}, sender's {Convert.ToHexString(senderPrivateKey)}, peer {Convert.ToHexString(peer)}, sender {Convert.ToHexString(sender)}");
			}
		}

		byte[] key = RandomBytes(random);
		byte[] untouchedPublicKey = CreateGuardedBuffer(0, X448.PublicKeyLength, 0);
		byte[] untouchedSecrets = CreateGuardedBuffer(0, 2 * X448.SharedSecretLength, 0);
		bool derivedForMultiple = X448Key.TryDerivePublicKeyAndSharedSecrets(EncodeInteger(4 * L), key, EncodeInteger(6), untouchedPublicKey, untouchedSecrets);
		List<string> accepted = [];

		foreach (byte[] peer in SmallOrderPublicKeys())
		{
			byte[] output = CreateGuardedBuffer(0, 2 * X448.SharedSecretLength, 0);

			if (X448Key.TryDeriveSharedSecrets(key, peer, Five, output) || output.AsSpan().ContainsAnyExcept(DestinationSentinel))
			{
				accepted.Add(Convert.ToHexString(peer));
			}
		}

		using (Assert.Multiple())
		{
			await Assert.That(failures).IsEmpty();
			await Assert.That(derivedForMultiple).IsFalse();
			await Assert.That(untouchedPublicKey).All(static value => value is DestinationSentinel);
			await Assert.That(untouchedSecrets).All(static value => value is DestinationSentinel);
			await Assert.That(accepted).IsEmpty();
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
