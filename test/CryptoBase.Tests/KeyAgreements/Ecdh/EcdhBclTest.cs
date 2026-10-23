using CryptoBase.Abstractions.KeyAgreements;
using CryptoBase.KeyAgreements.Ecdh;
using CryptoBase.Tests.EllipticCurves;
using System.Security.Cryptography;
using static CryptoBase.Tests.KeyAgreements.Ecdh.EcdhTestUtils;
using static CryptoBase.Tests.KeyAgreements.KeyAgreementTestUtils;

namespace CryptoBase.Tests.KeyAgreements.Ecdh;

public class EcdhBclTest
{
	private const int Iterations = 8;

	[Test]
	[GenerateGenericTest(typeof(EcdhP256))]
	[GenerateGenericTest(typeof(EcdhP384))]
	[GenerateGenericTest(typeof(EcdhP521))]
	public async Task SharedSecretsMatchThePlatform<T>() where T : class, IKeyAgreement<T>
	{
		CurveCase curve = CurveOf<T>();
		SkipUnlessSupported(curve);

		for (int i = 0; i < Iterations; ++i)
		{
			using T key = T.GenerateKey();
			using ECDiffieHellman bcl = ECDiffieHellman.Create(BclCurve(curve));
			using ECDiffieHellman ours = ECDiffieHellman.Create(new ECParameters { Curve = BclCurve(curve), Q = Decode(curve, ExportPublicKey(key)) });
			byte[] expected = bcl.DeriveRawSecretAgreement(ours.PublicKey);

			await Assert.That(DeriveSharedSecret(key, Encode(curve, bcl.ExportParameters(false).Q))).IsEquivalentTo(expected, CollectionOrdering.Matching);
		}
	}

	[Test]
	[GenerateGenericTest(typeof(EcdhP256))]
	[GenerateGenericTest(typeof(EcdhP384))]
	[GenerateGenericTest(typeof(EcdhP521))]
	public async Task PrivateKeysMoveBetweenImplementations<T>() where T : class, IKeyAgreement<T>
	{
		CurveCase curve = CurveOf<T>();
		SkipUnlessSupported(curve);

		for (int i = 0; i < Iterations; ++i)
		{
			using ECDiffieHellman bcl = ECDiffieHellman.Create(BclCurve(curve));
			using ECDiffieHellman bclPeer = ECDiffieHellman.Create(BclCurve(curve));
			ECParameters parameters = bcl.ExportParameters(true);
			using T fromBcl = T.ImportPrivateKey(Normalize(parameters.D, curve.ScalarLength));

			using T key = T.GenerateKey();
			using ECDiffieHellman toBcl = ECDiffieHellman.Create(new ECParameters { Curve = BclCurve(curve), D = ExportPrivateKey(key), Q = Decode(curve, ExportPublicKey(key)) });
			byte[] peerPublicKey = Encode(curve, bclPeer.ExportParameters(false).Q);

			using (Assert.Multiple())
			{
				await Assert.That(ExportPublicKey(fromBcl)).IsEquivalentTo(Encode(curve, parameters.Q), CollectionOrdering.Matching);
				await Assert.That(DeriveSharedSecret(fromBcl, peerPublicKey)).IsEquivalentTo(bcl.DeriveRawSecretAgreement(bclPeer.PublicKey), CollectionOrdering.Matching);
				await Assert.That(toBcl.DeriveRawSecretAgreement(bclPeer.PublicKey)).IsEquivalentTo(DeriveSharedSecret(key, peerPublicKey), CollectionOrdering.Matching);
			}
		}
	}

	private static ECCurve BclCurve(CurveCase curve)
	{
		return ECCurve.CreateFromValue(curve.Parameters.Oid);
	}

	private static void SkipUnlessSupported(CurveCase curve)
	{
		try
		{
			using ECDiffieHellman key = ECDiffieHellman.Create(BclCurve(curve));
			_ = key.DeriveRawSecretAgreement(key.PublicKey);
		}
		catch (PlatformNotSupportedException e)
		{
			Skip.Test($"The platform has no raw ECDH on the curve {curve.Parameters.Oid}: {e.Message}");
		}
	}

	// value in exactly length bytes, whatever padding the platform gives it.
	private static byte[] Normalize(byte[]? value, int length)
	{
		ArgumentNullException.ThrowIfNull(value);

		return CurveCase.EncodeInteger(ModulusCase.Decode(value), length);
	}

	private static byte[] Encode(CurveCase curve, ECPoint point)
	{
		return [0x04, .. Normalize(point.X, curve.FieldLength), .. Normalize(point.Y, curve.FieldLength)];
	}

	private static ECPoint Decode(CurveCase curve, byte[] encoding)
	{
		return new ECPoint { X = encoding.AsSpan(1, curve.FieldLength).ToArray(), Y = encoding.AsSpan(1 + curve.FieldLength, curve.FieldLength).ToArray() };
	}
}
