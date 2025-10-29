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

	[DoesNotReturn]
	public static T ThrowUnreachable<T>()
	{
		throw new InvalidOperationException(@"unreachable code!!!");
	}

	[DoesNotReturn]
	public static T ThrowArgumentOutOfRangeException<T>(string? paramName = default, string? message = default)
	{
		throw new ArgumentOutOfRangeException(paramName, message);
	}
}
