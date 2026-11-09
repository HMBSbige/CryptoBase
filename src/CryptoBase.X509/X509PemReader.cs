using CryptoBase.Internal;
using System.Diagnostics.CodeAnalysis;

namespace CryptoBase.X509;

internal ref struct X509PemReader(ReadOnlySpan<char> source, string label)
{
	private PemReader _reader = new(source);

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
