using CryptoBase.Abstractions.Kems;
using CryptoBase.Kems.Hybrid;

namespace CryptoBase.Tests.Kems.Hybrid;

internal static class ECMLKemTestUtils
{
	public static (byte[] Ciphertext, byte[] SharedSecret) Encapsulate<T>(T kem, ReadOnlySpan<byte> ephemeralPrivateKey, ReadOnlySpan<byte> message) where T : class, IKem<T>
	{
		byte[] ciphertext = new byte[T.CiphertextLength];
		byte[] sharedSecret = new byte[T.SharedSecretLength];

		switch (kem)
		{
			case SecP256r1MLKem768 secP256r1MLKem768:
			{
				secP256r1MLKem768.Encapsulate(ephemeralPrivateKey, message, ciphertext, sharedSecret);
				break;
			}
			case SecP384r1MLKem1024 secP384r1MLKem1024:
			{
				secP384r1MLKem1024.Encapsulate(ephemeralPrivateKey, message, ciphertext, sharedSecret);
				break;
			}
			default:
			{
				throw new NotSupportedException(typeof(T).Name);
			}
		}

		return (ciphertext, sharedSecret);
	}

	public static (byte[] Ec, byte[] MLKem) Split(byte[] value, int length)
	{
		return (value.AsSpan(0, length).ToArray(), value.AsSpan(length).ToArray());
	}
}
