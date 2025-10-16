using System.Security.Cryptography;

namespace CryptoBase;

internal static class ThrowHelper
{
	[DoesNotReturn]
	private static void ThrowAuthenticationTagMismatch()
	{
		throw new AuthenticationTagMismatchException();
	}

	public static void ThrowIfAuthenticationTagMismatch(ReadOnlySpan<byte> mac, ReadOnlySpan<byte> tag)
	{
		if (!CryptographicOperations.FixedTimeEquals(mac, tag))
		{
			ThrowAuthenticationTagMismatch();
		}
	}
}
