using CryptoBase.Signatures.EdDsa;
using System.Security.Cryptography;

namespace CryptoBase.Tests.Signatures.EdDsa;

internal static class Ed25519TestUtils
{
	public static byte[] ExportPrivateKey(Ed25519 key)
	{
		byte[] privateKey = new byte[Ed25519.PrivateKeyLength];
		key.ExportPrivateKey(privateKey);
		return privateKey;
	}

	public static byte[] ExportPublicKey(Ed25519 key)
	{
		byte[] publicKey = new byte[Ed25519.PublicKeyLength];
		key.ExportPublicKey(publicKey);
		return publicKey;
	}

	// Signs the message, or for Ed25519ph its SHA-512 hash. Ed25519ctx needs a context that is not empty.
	public static byte[] Sign(Ed25519 key, Ed25519Variant variant, byte[] message, byte[] context)
	{
		byte[] signature = new byte[Ed25519.SignatureLength];
		int written = variant switch
		{
			Ed25519Variant.Pure => key.Sign(message, signature),
			Ed25519Variant.Context => key.Sign(message, signature, context),
			_ => key.SignPreHash(SHA512.HashData(message), signature, context)
		};

		return written == signature.Length ? signature : throw new InvalidOperationException($"Sign wrote {written} bytes.");
	}

	public static bool Verify(Ed25519 key, Ed25519Variant variant, byte[] message, byte[] signature, byte[] context)
	{
		return variant switch
		{
			Ed25519Variant.Pure => key.Verify(message, signature),
			Ed25519Variant.Context => key.Verify(message, signature, context),
			_ => key.VerifyPreHash(SHA512.HashData(message), signature, context)
		};
	}
}
