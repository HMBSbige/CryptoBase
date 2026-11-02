using CryptoBase.Abstractions.Kems;
using CryptoBase.Abstractions.KeyAgreements;
using CryptoBase.Hpke;
using CryptoBase.Kems.Hybrid;
using CryptoBase.Kems.MLKem;
using CryptoBase.KeyAgreements.Ecdh;
using CryptoBase.KeyAgreements.Xdh;
using CryptoBase.Tests.KeyAgreements;
using static CryptoBase.Tests.TestUtils;

namespace CryptoBase.Tests.Kems;

// The public checks of TryDecapsulate on a ciphertext of the right length. KemContractTest needs an entry for every type it tests. CheckedRanges should hold only the bytes that the checks read: no test notices a range listed in excess, and within the listed ranges the tampering test asserts less.
// InvalidCiphertexts is the only data that catches a missing public check, so it needs a ciphertext for each kind of rejection. KemContractTest expects an unrelated key to give the same result, which holds only while the checks read the ciphertext alone.
internal sealed record KemCiphertextChecks((int Offset, int Length)[] CheckedRanges, byte[][] InvalidCiphertexts)
{
	public static KemCiphertextChecks Of<T>() where T : class, IKem<T>
	{
		if (typeof(T) == typeof(MLKem512) || typeof(T) == typeof(MLKem768) || typeof(T) == typeof(MLKem1024))
		{
			return new KemCiphertextChecks([], []);
		}

		if (typeof(T) == typeof(SecP256r1MLKem768))
		{
			return ECMLKem<EcdhP256>(T.CiphertextLength);
		}

		if (typeof(T) == typeof(SecP384r1MLKem1024))
		{
			return ECMLKem<EcdhP384>(T.CiphertextLength);
		}

		if (typeof(T) == typeof(X25519MLKem768))
		{
			return MLKemX25519(T.CiphertextLength);
		}

		if (typeof(T) == typeof(DhKemP256))
		{
			return DhKem<EcdhP256>();
		}

		if (typeof(T) == typeof(DhKemP384))
		{
			return DhKem<EcdhP384>();
		}

		if (typeof(T) == typeof(DhKemP521))
		{
			return DhKem<EcdhP521>();
		}

		if (typeof(T) == typeof(DhKemX25519))
		{
			return DhKem<X25519>();
		}

		throw new NotSupportedException(typeof(T).Name);
	}

	public bool TouchesCheckedRange(ReadOnlySpan<byte> original, ReadOnlySpan<byte> tampered)
	{
		foreach ((int offset, int length) in CheckedRanges)
		{
			if (!original.Slice(offset, length).SequenceEqual(tampered.Slice(offset, length)))
			{
				return true;
			}
		}

		return false;
	}

	// The ciphertext is an ephemeral public key.
	private static KemCiphertextChecks DhKem<TEcdh>() where TEcdh : class, IKeyAgreement<TEcdh>
	{
		return new KemCiphertextChecks([(0, TEcdh.PublicKeyLength)], KeyAgreementChecks.Of<TEcdh>().InvalidPublicKeys);
	}

	private static KemCiphertextChecks ECMLKem<TEcdh>(int ciphertextLength) where TEcdh : class, IKeyAgreement<TEcdh>
	{
		byte[] mlKemCiphertext = CreateDeterministicSource(ciphertextLength - TEcdh.PublicKeyLength);
		byte[][] invalid = [.. KeyAgreementChecks.Of<TEcdh>().InvalidPublicKeys.Select(publicKey => Concat(publicKey, mlKemCiphertext))];
		return new KemCiphertextChecks([(0, TEcdh.PublicKeyLength)], invalid);
	}

	// The X25519 part follows the ML-KEM ciphertext.
	private static KemCiphertextChecks MLKemX25519(int ciphertextLength)
	{
		int offset = ciphertextLength - X25519.PublicKeyLength;
		byte[] mlKemCiphertext = CreateDeterministicSource(offset);
		byte[][] invalid = [.. KeyAgreementChecks.Of<X25519>().InvalidPublicKeys.Select(publicKey => Concat(mlKemCiphertext, publicKey))];
		return new KemCiphertextChecks([(offset, X25519.PublicKeyLength)], invalid);
	}
}
