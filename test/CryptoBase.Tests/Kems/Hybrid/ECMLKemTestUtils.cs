using CryptoBase.Abstractions.Kems;
using CryptoBase.EllipticCurves;
using CryptoBase.Hashes.Sha3;
using CryptoBase.Internal;
using CryptoBase.Kems.Hybrid;
using CryptoBase.Kems.MLKem;
using CryptoBase.KeyAgreements.Xdh;
using System.Diagnostics.CodeAnalysis;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

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
			case X25519MLKem768 x25519MLKem768:
			{
				x25519MLKem768.Encapsulate(ephemeralPrivateKey, message, ciphertext, sharedSecret);
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

	// The bytes of each field of the key an instance holds.
	public static Dictionary<string, byte[]> KeyContents<T>(T kem) where T : class, IKem<T>
	{
		return kem switch
		{
			SecP256r1MLKem768 secP256r1MLKem768 => FieldContents(KeyOf(secP256r1MLKem768)),
			SecP384r1MLKem1024 secP384r1MLKem1024 => FieldContents(KeyOf(secP384r1MLKem1024)),
			X25519MLKem768 x25519MLKem768 => FieldContents(KeyOf(x25519MLKem768)),
			_ => throw new InvalidOperationException($"{typeof(T).Name} has no key field.")
		};
	}

	[UnsafeAccessor(UnsafeAccessorKind.Field, Name = "_key")]
	private static extern ref ECMLKemKey<P256Curve, P256Field52, P256Order, MLKem768Parameters> KeyOf(SecP256r1MLKem768 kem);

	[UnsafeAccessor(UnsafeAccessorKind.Field, Name = "_key")]
	private static extern ref ECMLKemKey<P384Curve, P384Field56, P384Order, MLKem1024Parameters> KeyOf(SecP384r1MLKem1024 kem);

	[UnsafeAccessor(UnsafeAccessorKind.Field, Name = "_key")]
	private static extern ref X25519MLKemKey<MLKem768Parameters> KeyOf(X25519MLKem768 kem);

	private static Dictionary<string, byte[]> FieldContents<[DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.PublicFields | DynamicallyAccessedMemberTypes.NonPublicFields)] TValue>(TValue value) where TValue : struct
	{
		object boxed = value;
		return typeof(TValue).GetFields(BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic).ToDictionary(static field => field.Name, field => Contents(field.GetValue(boxed)));
	}

	// The polynomials of ML-KEM are an array; everything else is a struct without references.
	private static byte[] Contents(object? value)
	{
		return value switch
		{
			null => [],
			short[] array => MemoryMarshal.AsBytes(array.AsSpan()).ToArray(),
			MLKemKey<MLKem768Parameters> key => [.. FieldContents(key).Values.SelectMany(static bytes => bytes)],
			MLKemKey<MLKem1024Parameters> key => [.. FieldContents(key).Values.SelectMany(static bytes => bytes)],
			ECKey<P256Curve, P256Field52, P256Order> key => Bytes(key),
			ECKey<P384Curve, P384Field56, P384Order> key => Bytes(key),
			X25519Key key => Bytes(key),
			InlineArray32<byte> bytes => Bytes(bytes),
			KeccakSponge<KeccakRate136> sponge => Bytes(sponge),
			int number => Bytes(number),
			bool flag => Bytes(flag),
			_ => throw new InvalidOperationException($"The test does not know how to check {value.GetType().Name}.")
		};
	}

	private static byte[] Bytes<TValue>(TValue value) where TValue : struct
	{
		return MemoryMarshal.AsBytes(new ReadOnlySpan<TValue>(in value)).ToArray();
	}
}
