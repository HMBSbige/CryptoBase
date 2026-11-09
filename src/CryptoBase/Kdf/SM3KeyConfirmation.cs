using CryptoBase.Hashes;
using CryptoBase.Hashes.SM3;

namespace CryptoBase.Kdf;

internal static class SM3KeyConfirmation
{
	// Cuts confirmation and peerConfirmation to length bytes, once they are that long and no two of the outputs overlap.
	internal static void CheckOutputs(ReadOnlySpan<byte> sharedKey, ref Span<byte> confirmation, ref Span<byte> peerConfirmation, int length)
	{
		ArgumentOutOfRangeException.ThrowIfLessThan(confirmation.Length, length, nameof(confirmation));
		ArgumentOutOfRangeException.ThrowIfLessThan(peerConfirmation.Length, length, nameof(peerConfirmation));

		confirmation = confirmation.Slice(0, length);
		peerConfirmation = peerConfirmation.Slice(0, length);

		if (sharedKey.Overlaps(confirmation) || sharedKey.Overlaps(peerConfirmation) || confirmation.Overlaps(peerConfirmation))
		{
			ThrowHelper.ThrowOutputsOverlap(nameof(sharedKey));
		}
	}

	// SM3(tag ‖ part ‖ inner), Hv in SM9.
	[SkipLocalsInit]
	internal static void Compute(byte tag, ReadOnlySpan<byte> part, ReadOnlySpan<byte> inner, Span<byte> destination)
	{
		SM3Core hash = HashCore.Create<SM3Core>();
		HashCore.Append(ref hash, new ReadOnlySpan<byte>(in tag));
		HashCore.Append(ref hash, part);
		HashCore.Append(ref hash, inner);
		HashCore.Finalize(ref hash, destination);
		hash.ZeroMemory();
	}
}
