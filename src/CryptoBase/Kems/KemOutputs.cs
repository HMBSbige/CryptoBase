namespace CryptoBase.Kems;

internal static class KemOutputs
{
	internal static void ThrowIfInvalid(Span<byte> ciphertext, int ciphertextLength, Span<byte> sharedSecret, int sharedSecretLength)
	{
		ArgumentOutOfRangeException.ThrowIfLessThan(ciphertext.Length, ciphertextLength, nameof(ciphertext));
		ArgumentOutOfRangeException.ThrowIfLessThan(sharedSecret.Length, sharedSecretLength, nameof(sharedSecret));

		if (ByteSpans.Overlaps(ciphertext.Slice(0, ciphertextLength), sharedSecret.Slice(0, sharedSecretLength)))
		{
			ThrowHelper.ThrowOutputsOverlap(nameof(sharedSecret));
		}
	}
}
