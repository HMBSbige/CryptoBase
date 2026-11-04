using CryptoBase.Signatures.EdDsa;

namespace CryptoBase.Tests.Signatures.EdDsa;

internal static class Ed448TestUtils
{
	public static byte[] ExportPrivateKey(Ed448 key)
	{
		byte[] privateKey = new byte[Ed448.PrivateKeyLength];
		key.ExportPrivateKey(privateKey);
		return privateKey;
	}

	public static byte[] ExportPublicKey(Ed448 key)
	{
		byte[] publicKey = new byte[Ed448.PublicKeyLength];
		key.ExportPublicKey(publicKey);
		return publicKey;
	}

	public static byte[] Sign(Ed448 key, Ed448Variant variant, byte[] message, byte[] context)
	{
		byte[] signature = new byte[Ed448.SignatureLength];
		int written = variant switch
		{
			Ed448Variant.Pure => key.Sign(message, signature, context),
			_ => key.SignPreHash(Ed448Reference.Input(variant, message), signature, context)
		};

		return written == signature.Length ? signature : throw new InvalidOperationException($"Sign wrote {written} bytes.");
	}

	public static bool Verify(Ed448 key, Ed448Variant variant, byte[] message, byte[] signature, byte[] context)
	{
		return variant switch
		{
			Ed448Variant.Pure => key.Verify(message, signature, context),
			_ => key.VerifyPreHash(Ed448Reference.Input(variant, message), signature, context)
		};
	}
}
