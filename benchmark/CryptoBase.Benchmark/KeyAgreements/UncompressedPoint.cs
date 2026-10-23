using Org.BouncyCastle.Crypto.Parameters;
using System.Security.Cryptography;

namespace CryptoBase.Benchmark.KeyAgreements;

internal static class UncompressedPoint
{
	internal static ECParameters ToBcl(ECCurve curve, ReadOnlySpan<byte> point)
	{
		int length = (point.Length - 1) / 2;
		return new ECParameters
		{
			Curve = curve,
			Q = new ECPoint { X = point.Slice(1, length).ToArray(), Y = point.Slice(1 + length, length).ToArray() }
		};
	}

	internal static ECPublicKeyParameters ToBouncyCastle(ECDomainParameters domain, ReadOnlySpan<byte> point)
	{
		return new ECPublicKeyParameters(domain.Curve.DecodePoint(point), domain);
	}
}
