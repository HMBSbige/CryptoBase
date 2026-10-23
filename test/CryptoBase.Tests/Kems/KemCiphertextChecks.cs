using CryptoBase.Abstractions.Kems;
using CryptoBase.Kems.MLKem;

namespace CryptoBase.Tests.Kems;

// The public checks of TryDecapsulate on a ciphertext of the right length. KemContractTest needs an entry for every type it tests.
// CheckedRanges should hold only the bytes that the checks read: no test notices a range listed in excess, and within the listed ranges the
// tampering test asserts less.
// InvalidCiphertexts is the only data that catches a missing public check, so it needs a ciphertext for each kind of rejection.
// KemContractTest expects an unrelated key to give the same result, which holds only while the checks read the ciphertext alone.
internal sealed record KemCiphertextChecks((int Offset, int Length)[] CheckedRanges, byte[][] InvalidCiphertexts)
{
	public static KemCiphertextChecks Of<T>() where T : class, IKem<T>
	{
		if (typeof(T) == typeof(MLKem512) || typeof(T) == typeof(MLKem768) || typeof(T) == typeof(MLKem1024))
		{
			return new KemCiphertextChecks([], []);
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
}
