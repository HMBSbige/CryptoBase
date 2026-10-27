using CryptoBase.Abstractions.KeyAgreements;
using CryptoBase.KeyAgreements.Ecdh;
using CryptoBase.Tests.EllipticCurves;
using System.Numerics;
using static CryptoBase.Tests.KeyAgreements.Ecdh.EcdhTestUtils;
using static CryptoBase.Tests.KeyAgreements.KeyAgreementTestUtils;
using static CryptoBase.Tests.TestUtils;

namespace CryptoBase.Tests.KeyAgreements.Ecdh;

[GenerateGenericTest(typeof(EcdhP256))]
[GenerateGenericTest(typeof(EcdhP384))]
[GenerateGenericTest(typeof(EcdhP521))]
public class EcdhTest<T> where T : class, IKeyAgreement<T>
{
	[Test]
	public async Task LengthsFollowTheCurve()
	{
		CurveCase curve = CurveOf<T>();

		await Assert.That((T.PrivateKeyLength, T.PublicKeyLength, T.SharedSecretLength)).IsEqualTo((curve.ScalarLength, 1 + 2 * curve.FieldLength, curve.FieldLength));
	}

	[Test]
	public async Task ExtremePrivateKeysGiveTheGeneratorAndItsNegation()
	{
		CurveCase curve = CurveOf<T>();
		CurvePoint g = curve.Reference.Generator;
		using T one = T.ImportPrivateKey(curve.EncodeScalar(BigInteger.One));
		using T last = T.ImportPrivateKey(curve.EncodeScalar(curve.Order - 1));

		using (Assert.Multiple())
		{
			await Assert.That(ExportPublicKey(one)).IsEquivalentTo(curve.EncodePoint(g), CollectionOrdering.Matching);
			await Assert.That(ExportPublicKey(last)).IsEquivalentTo(curve.EncodePoint(g with { Y = curve.Reference.P - g.Y }), CollectionOrdering.Matching);
		}
	}

	[Test]
	public async Task SharedSecretIsTheXCoordinate()
	{
		CurveCase curve = CurveOf<T>();
		using T one = T.ImportPrivateKey(curve.EncodeScalar(BigInteger.One));
		using T last = T.ImportPrivateKey(curve.EncodeScalar(curve.Order - 1));
		using T key = T.GenerateKey();
		using T peer = T.GenerateKey();
		byte[] peerPublicKey = ExportPublicKey(peer);
		CurvePoint q = curve.DecodePoint(peerPublicKey);
		byte[] negated = curve.EncodePoint(q with { Y = curve.Reference.P - q.Y });
		byte[] expected = curve.EncodeCoordinate(q.X);

		using (Assert.Multiple())
		{
			await Assert.That(DeriveSharedSecret(one, peerPublicKey)).IsEquivalentTo(expected, CollectionOrdering.Matching);
			await Assert.That(DeriveSharedSecret(last, peerPublicKey)).IsEquivalentTo(expected, CollectionOrdering.Matching);
			await Assert.That(DeriveSharedSecret(one, negated)).IsEquivalentTo(expected, CollectionOrdering.Matching);
			await Assert.That(DeriveSharedSecret(key, negated)).IsEquivalentTo(DeriveSharedSecret(key, peerPublicKey), CollectionOrdering.Matching);
		}
	}

	[Test]
	public async Task ReducedCoordinatesAreAccepted()
	{
		CurveCase curve = CurveOf<T>();
		CurvePoint point = curve.Reference.PointWithXFrom(BigInteger.Zero);
		byte[] expected = curve.EncodeCoordinate(point.X);
		using T one = T.ImportPrivateKey(curve.EncodeScalar(BigInteger.One));
		byte[] unreduced = curve.EncodePoint(point with { X = point.X + curve.Reference.P });

		using (Assert.Multiple())
		{
			await Assert.That(KeyAgreementChecks.Of<T>().InvalidPublicKeys).Contains(key => key.AsSpan().SequenceEqual(unreduced));
			await Assert.That(DeriveSharedSecret(one, curve.EncodePoint(point))).IsEquivalentTo(expected, CollectionOrdering.Matching);
			await Assert.That(DeriveSharedSecret(one, curve.EncodePoint(point with { Y = curve.Reference.P - point.Y }))).IsEquivalentTo(expected, CollectionOrdering.Matching);
		}
	}

	[Test]
	public async Task KeyOperationsDoNotAllocate()
	{
		// Without optimization, every read of a constant ReadOnlySpan<ulong>, such as the field modulus, allocates a field handle.
		SkipUnlessOptimized<T>();

		using T key = T.GenerateKey();
		using T peer = T.GenerateKey();
		byte[] privateKey = new byte[T.PrivateKeyLength];
		byte[] publicKey = new byte[T.PublicKeyLength];
		byte[] peerPublicKey = ExportPublicKey(peer);
		byte[] invalidPublicKey = new byte[T.PublicKeyLength];
		byte[] sharedSecret = new byte[T.SharedSecretLength];

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

	private static bool Exercise(T key, byte[] privateKey, byte[] publicKey, byte[] peerPublicKey, byte[] invalidPublicKey, byte[] sharedSecret)
	{
		key.ExportPrivateKey(privateKey);
		key.ExportPublicKey(publicKey);
		bool rejected = !key.TryDeriveSharedSecret(invalidPublicKey, sharedSecret);
		return key.TryDeriveSharedSecret(peerPublicKey, sharedSecret) & rejected;
	}
}

public class EcdhTest
{
	[Test]
	public async Task LengthsAreFixed()
	{
		using (Assert.Multiple())
		{
			await Assert.That((EcdhP256.PrivateKeyLength, EcdhP256.PublicKeyLength, EcdhP256.SharedSecretLength)).IsEqualTo((32, 65, 32));
			await Assert.That((EcdhP384.PrivateKeyLength, EcdhP384.PublicKeyLength, EcdhP384.SharedSecretLength)).IsEqualTo((48, 97, 48));
			await Assert.That((EcdhP521.PrivateKeyLength, EcdhP521.PublicKeyLength, EcdhP521.SharedSecretLength)).IsEqualTo((66, 133, 66));
		}
	}
}
