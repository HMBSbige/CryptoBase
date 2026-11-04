using System.Numerics;
using static CryptoBase.Tests.EllipticCurves.Curve448.Curve448Reference;

namespace CryptoBase.Tests.KeyAgreements.Xdh;

internal static class X448TestUtils
{
	// Order dividing 4: 0, 1 and p − 1, with 0 and 1 also as p and p + 1; 2p − 1 does not fit.
	public static byte[][] SmallOrderPublicKeys()
	{
		BigInteger[] values = [0, 1, P - 1, P, P + 1];
		return [.. values.Select(static u => EncodeInteger(u))];
	}
}
