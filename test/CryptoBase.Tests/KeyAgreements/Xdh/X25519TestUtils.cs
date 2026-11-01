using System.Numerics;
using static CryptoBase.Tests.EllipticCurves.Curve25519.Curve25519Reference;

namespace CryptoBase.Tests.KeyAgreements.Xdh;

internal static class X25519TestUtils
{
	// Every encoding of a u-coordinate whose point has an order dividing 8, so that X25519 gives 0 with every private key: those of the torsion points of the curve, 0, 1 and the two of order 8, and p − 1, of order 4 on the twist; 0 and 1 also as p and p + 1; and each of these with bit 255 set.
	public static byte[][] SmallOrderPublicKeys()
	{
		IEnumerable<BigInteger> values = TorsionPoints().Select(ToMontgomeryU).Append(P - 1).Distinct();
		List<byte[]> encodings = [];

		foreach (BigInteger u in values.Concat([P, P + 1]))
		{
			byte[] encoded = EncodeInteger(u);
			byte[] withTopBit = (byte[])encoded.Clone();
			withTopBit[31] |= 0x80;
			encodings.Add(encoded);
			encodings.Add(withTopBit);
		}

		return [.. encodings];
	}
}
