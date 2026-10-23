using CryptoBase.Abstractions.KeyAgreements;
using static CryptoBase.Tests.TestUtils;

namespace CryptoBase.Tests.KeyAgreements;

internal static class KeyAgreementTestUtils
{
	public static byte[] ExportPrivateKey<T>(T key) where T : class, IKeyAgreement<T>
	{
		byte[] privateKey = new byte[T.PrivateKeyLength];
		key.ExportPrivateKey(privateKey);
		return privateKey;
	}

	public static byte[] ExportPublicKey<T>(T key) where T : class, IKeyAgreement<T>
	{
		byte[] publicKey = new byte[T.PublicKeyLength];
		key.ExportPublicKey(publicKey);
		return publicKey;
	}

	public static byte[] DeriveSharedSecret<T>(T key, ReadOnlySpan<byte> peerPublicKey) where T : class, IKeyAgreement<T>
	{
		(bool result, byte[] sharedSecret) = TryDeriveSharedSecret(key, peerPublicKey);

		if (!result)
		{
			Assert.Fail("TryDeriveSharedSecret returned false.");
		}

		return sharedSecret;
	}

	// Output starts filled with DestinationSentinel, so a false result can be checked to leave it unchanged.
	public static (bool Result, byte[] Output) TryDeriveSharedSecret<T>(T key, ReadOnlySpan<byte> peerPublicKey) where T : class, IKeyAgreement<T>
	{
		byte[] output = CreateGuardedBuffer(0, T.SharedSecretLength, 0);
		bool result = key.TryDeriveSharedSecret(peerPublicKey, output);
		return (result, output);
	}
}
