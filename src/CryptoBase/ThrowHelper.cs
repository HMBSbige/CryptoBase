namespace CryptoBase;

[StackTraceHidden]
internal static class ThrowHelper
{
	[DoesNotReturn]
	private static void ThrowAuthenticationTagMismatch()
	{
		throw new AuthenticationTagMismatchException();
	}

	public static void ThrowIfAuthenticationTagMismatch(ReadOnlySpan<byte> expectedTag, ReadOnlySpan<byte> tag)
	{
		if (!CryptographicOperations.FixedTimeEquals(expectedTag, tag))
		{
			ThrowAuthenticationTagMismatch();
		}
	}

	[DoesNotReturn]
	public static T ThrowUnreachable<T>() where T : allows ref struct
	{
		throw new InvalidOperationException(@"unreachable code!!!");
	}

	[DoesNotReturn]
	public static T ThrowArgumentOutOfRangeException<T>(string? paramName = default, string? message = default)
	{
		throw new ArgumentOutOfRangeException(paramName, message);
	}

	[DoesNotReturn]
	public static void ThrowDataLimitExceeded(string? paramName = default)
	{
		throw new ArgumentOutOfRangeException(paramName, "Data limit exceeded!");
	}

	[DoesNotReturn]
	public static void ThrowNotSupported(string? message = default)
	{
		throw new NotSupportedException(message);
	}
}
