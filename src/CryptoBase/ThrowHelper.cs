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
	public static void ThrowInputOutputOverlap(string parameterName)
	{
		throw new ArgumentException("The input and output buffers must not overlap.", parameterName);
	}

	[DoesNotReturn]
	public static void ThrowOutputsOverlap(string parameterName)
	{
		throw new ArgumentException("The output buffers must not overlap.", parameterName);
	}

	[DoesNotReturn]
	public static void ThrowInvalidKey(string parameterName)
	{
		throw new ArgumentException("The key is invalid.", parameterName);
	}

	[DoesNotReturn]
	public static void ThrowMissingKey(string keyName)
	{
		throw new InvalidOperationException($"The instance does not hold the {keyName}.");
	}

	[DoesNotReturn]
	public static void ThrowUnsupportedSignatureAlgorithm(string parameterName)
	{
		throw new ArgumentException("The key does not support the signature algorithm.", parameterName);
	}

	[DoesNotReturn]
	public static void ThrowUnsupportedHashAlgorithm(string parameterName)
	{
		throw new ArgumentException("The hash algorithm is not supported.", parameterName);
	}

	[DoesNotReturn]
	public static void ThrowHashLengthMismatch(string parameterName)
	{
		throw new ArgumentException("The hash does not have the output length of its algorithm.", parameterName);
	}

	[DoesNotReturn]
	public static T ThrowArgumentOutOfRangeException<T>(string? paramName = default, string? message = default)
	{
		throw new ArgumentOutOfRangeException(paramName, message);
	}

	[DoesNotReturn]
	public static void ThrowDataLimitExceeded(string paramName)
	{
		throw new ArgumentOutOfRangeException(paramName, "Data limit exceeded!");
	}

	// length is that of the ciphertext, or −1 if it would exceed int.MaxValue.
	public static void ThrowIfInvalidEncryptionBuffers(ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> destination, int length)
	{
		if (plaintext.IsEmpty)
		{
			throw new ArgumentException("The plaintext must not be empty.", nameof(plaintext));
		}

		if (length < 0)
		{
			throw new ArgumentException("The ciphertext would be longer than int.MaxValue bytes.", nameof(plaintext));
		}

		ArgumentOutOfRangeException.ThrowIfLessThan(destination.Length, length, nameof(destination));

		if (plaintext.Overlaps(destination))
		{
			ThrowInputOutputOverlap(nameof(destination));
		}
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static void ThrowIfXofReading([DoesNotReturnIf(true)] bool reading)
	{
		if (reading)
		{
			ThrowXofReading();
		}
	}

	[DoesNotReturn]
	private static void ThrowXofReading()
	{
		throw new InvalidOperationException("This operation is not supported once the output has started reading; call Reset first.");
	}
}
