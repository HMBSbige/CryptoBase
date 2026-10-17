using System.Diagnostics.CodeAnalysis;

namespace CryptoBase;

[StackTraceHidden]
internal static class ThrowHelper
{
	[DoesNotReturn]
	public static void ThrowSourceDestinationOverlap(string parameterName)
	{
		throw new ArgumentException("The source and destination buffers must not overlap unless they have the same starting address.", parameterName);
	}

	[DoesNotReturn]
	public static void ThrowSourceNotBlockAligned(string parameterName)
	{
		throw new ArgumentException("Source length must be a multiple of the block size.", parameterName);
	}

	[DoesNotReturn]
	public static void ThrowTagDestinationOverlap(string parameterName)
	{
		throw new ArgumentException("The tag and destination buffers must not overlap.", parameterName);
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
}
