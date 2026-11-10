using CryptoBase.Internal;
using System.Diagnostics.CodeAnalysis;

namespace CryptoBase.X509;

// Reads the PEM blocks (RFC 7468) of a text that have one label; other blocks and the text around the blocks are ignored.
internal ref struct X509PemReader(ReadOnlySpan<char> source, string label)
{
	private PemReader _reader = new(source);

	public static byte[] ReadFirst(ReadOnlySpan<char> source, string label, string parameterName)
	{
		X509PemReader reader = new(source, label);
		return reader.TryRead(out byte[]? encoded) ? encoded : throw new ArgumentException($"The text holds no {label} block.", parameterName);
	}

	public static T[] ReadAll<T>(ReadOnlySpan<char> source, string label, Func<byte[], T> decode)
	{
		X509PemReader reader = new(source, label);
		List<T> values = [];

		while (reader.TryRead(out byte[]? encoded))
		{
			values.Add(decode(encoded));
		}

		return [.. values];
	}

	public bool TryRead([NotNullWhen(true)] out byte[]? encoded)
	{
		while (_reader.TryRead(out ReadOnlySpan<char> found, out ReadOnlySpan<char> base64Data, out int decodedLength))
		{
			if (found.SequenceEqual(label))
			{
				encoded = GC.AllocateUninitializedArray<byte>(decodedLength);
				PemReader.Decode(base64Data, encoded);
				return true;
			}
		}

		encoded = null;
		return false;
	}
}
