using CryptoBase.Abstractions.KeyAgreements;
using CryptoBase.Tests.EllipticCurves;
using System.Numerics;
using static CryptoBase.Tests.KeyAgreements.Ecdh.EcdhTestUtils;

namespace CryptoBase.Tests.KeyAgreements;

// Keys of the right length that a type rejects from their contents alone. KeyAgreementContractTest needs an entry for every type it tests. These lists are the only data that catch a missing check, so each needs a key for each kind of rejection.
internal sealed record KeyAgreementChecks(byte[][] InvalidPrivateKeys, byte[][] InvalidPublicKeys)
{
	public static KeyAgreementChecks Of<T>() where T : class, IKeyAgreement<T>
	{
		return Ecdh(CurveOf<T>());
	}

	private static KeyAgreementChecks Ecdh(CurveCase curve)
	{
		ECReference reference = curve.Reference;
		CurvePoint g = reference.Generator;
		byte[] generator = curve.EncodePoint(g);
		CurvePoint small = reference.PointWithXFrom(BigInteger.Zero);
		BigInteger maximum = (BigInteger.One << 8 * curve.FieldLength) - 1;
		List<byte[]> publicKeys = [];

		foreach (byte prefix in (byte[])[0x00, 0x02, 0x03, 0x05, 0x06, 0x07])
		{
			byte[] encoding = (byte[])generator.Clone();
			encoding[0] = prefix;
			publicKeys.Add(encoding);
		}

		// A coordinate of p or more; the first reduces to a point on the curve.
		publicKeys.Add(curve.EncodePoint(small with { X = small.X + reference.P }));
		publicKeys.Add(curve.EncodePoint(g with { X = reference.P }));
		publicKeys.Add(curve.EncodePoint(g with { X = maximum }));
		publicKeys.Add(curve.EncodePoint(g with { Y = reference.P }));
		publicKeys.Add(curve.EncodePoint(g with { Y = maximum }));

		publicKeys.Add(curve.EncodePoint(g with { Y = g.Y + 1 }));
		publicKeys.Add(curve.EncodePoint(new CurvePoint(BigInteger.Zero, BigInteger.Zero)));
		publicKeys.Add(new byte[generator.Length]);

		int length = curve.ScalarLength;
		List<byte[]> privateKeys = [curve.EncodeScalar(BigInteger.Zero), curve.EncodeScalar(curve.Order), Enumerable.Repeat((byte)0xFF, length).ToArray()];
		BigInteger top = curve.Order >> 8 * (length - 1);

		// The least key with a leading byte above that of n, where n leaves room for one.
		if (top < 0xFF)
		{
			privateKeys.Add(curve.EncodeScalar(top + 1 << 8 * (length - 1)));
		}

		return new KeyAgreementChecks([.. privateKeys], [.. publicKeys]);
	}
}
