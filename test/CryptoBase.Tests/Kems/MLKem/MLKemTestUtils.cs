using CryptoBase.Abstractions.Kems;
using CryptoBase.Kems.MLKem;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;

namespace CryptoBase.Tests.Kems.MLKem;

internal static class MLKemTestUtils
{
	[UnsafeAccessor(UnsafeAccessorKind.Field, Name = "_key")]
	public static extern ref MLKemKey<MLKem512Parameters> KeyOf(MLKem512 kem);

	[UnsafeAccessor(UnsafeAccessorKind.Field, Name = "_key")]
	public static extern ref MLKemKey<MLKem768Parameters> KeyOf(MLKem768 kem);

	[UnsafeAccessor(UnsafeAccessorKind.Field, Name = "_key")]
	public static extern ref MLKemKey<MLKem1024Parameters> KeyOf(MLKem1024 kem);

	// ML-KEM.Encaps_internal with a chosen m, which IKem does not expose.
	public static (byte[] Ciphertext, byte[] SharedSecret) Encapsulate<T>(T kem, ReadOnlySpan<byte> message) where T : class, IKem<T>
	{
		byte[] ciphertext = new byte[T.CiphertextLength];
		byte[] sharedSecret = new byte[T.SharedSecretLength];

		switch (kem)
		{
			case MLKem512 mlKem512:
			{
				mlKem512.Encapsulate(message, ciphertext, sharedSecret);
				break;
			}
			case MLKem768 mlKem768:
			{
				mlKem768.Encapsulate(message, ciphertext, sharedSecret);
				break;
			}
			case MLKem1024 mlKem1024:
			{
				mlKem1024.Encapsulate(message, ciphertext, sharedSecret);
				break;
			}
			default:
			{
				throw new NotSupportedException(typeof(T).Name);
			}
		}

		return (ciphertext, sharedSecret);
	}

	public static MLKemAlgorithm BclAlgorithm<T>() where T : class, IKem<T>
	{
		if (typeof(T) == typeof(MLKem512))
		{
			return MLKemAlgorithm.MLKem512;
		}

		if (typeof(T) == typeof(MLKem768))
		{
			return MLKemAlgorithm.MLKem768;
		}

		return typeof(T) == typeof(MLKem1024) ? MLKemAlgorithm.MLKem1024 : throw new NotSupportedException(typeof(T).Name);
	}
}
