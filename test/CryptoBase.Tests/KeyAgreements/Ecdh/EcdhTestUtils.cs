using CryptoBase.Abstractions.KeyAgreements;
using CryptoBase.KeyAgreements.Ecdh;
using CryptoBase.Tests.EllipticCurves;
using System.Security.Cryptography;

namespace CryptoBase.Tests.KeyAgreements.Ecdh;

internal static class EcdhTestUtils
{
	public static CurveCase CurveOf<T>() where T : class, IKeyAgreement<T>
	{
		return CurveCase.Named(typeof(T).Name switch
		{
			nameof(EcdhP256) => "secp256r1",
			nameof(EcdhP384) => "secp384r1",
			nameof(EcdhP521) => "secp521r1",
			_ => throw new NotSupportedException(typeof(T).Name)
		});
	}

	public static ECCurve BclCurve(CurveCase curve)
	{
		return ECCurve.CreateFromValue(curve.Parameters.Oid);
	}

	public static void SkipUnlessSupported(CurveCase curve)
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

	public static byte[] Normalize(byte[]? value, int length)
	{
		ArgumentNullException.ThrowIfNull(value);

		return CurveCase.EncodeInteger(ModulusCase.Decode(value), length);
	}

	public static byte[] Encode(CurveCase curve, ECPoint point)
	{
		return [0x04, .. Normalize(point.X, curve.FieldLength), .. Normalize(point.Y, curve.FieldLength)];
	}

	public static ECPoint Decode(CurveCase curve, byte[] encoding)
	{
		return new ECPoint { X = encoding.AsSpan(1, curve.FieldLength).ToArray(), Y = encoding.AsSpan(1 + curve.FieldLength, curve.FieldLength).ToArray() };
	}
}
