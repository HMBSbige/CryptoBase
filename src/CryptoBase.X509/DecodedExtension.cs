namespace CryptoBase.X509;

// The value of an extension that a certificate decodes on first use: the decoded value, the default without the extension, or the error of a value that does not decode.
internal readonly struct DecodedExtension<T>(T? value, AsnContentException? error)
{
	public T? Value { get; } = value;

	public AsnContentException? Error { get; } = error;

	// A new exception for each call, as threads may throw at once.
	public T? GetValueOrThrow(string name)
	{
		if (Error is not null)
		{
			throw new CryptographicException($"The {name} extension is invalid.", Error);
		}

		return Value;
	}

	public static DecodedExtension<T> Decode(ReadOnlyMemory<byte> value, Func<ReadOnlyMemory<byte>, T> read)
	{
		try
		{
			return new DecodedExtension<T>(read(value), null);
		}
		catch (AsnContentException e)
		{
			return new DecodedExtension<T>(default, e);
		}
	}
}
