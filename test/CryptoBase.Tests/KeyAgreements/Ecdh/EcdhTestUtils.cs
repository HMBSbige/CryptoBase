using CryptoBase.Abstractions.KeyAgreements;
using CryptoBase.KeyAgreements.Ecdh;
using CryptoBase.Tests.EllipticCurves;

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
}
