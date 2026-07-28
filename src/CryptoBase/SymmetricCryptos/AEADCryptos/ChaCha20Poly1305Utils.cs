using CryptoBase.Macs.Poly1305;
using CryptoBase.SymmetricCryptos.StreamCryptos;

namespace CryptoBase.SymmetricCryptos.AEADCryptos;

internal static class ChaCha20Poly1305Utils
{
	private static ReadOnlySpan<byte> Init => "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"u8;

	/// <summary>
	/// The counter of <paramref name="chacha20"/> must already be set to 0 before calling.
	/// </summary>
	[SkipLocalsInit]
	internal static void ComputeTag(SnuffleCrypto chacha20, ReadOnlySpan<byte> associatedData, ReadOnlySpan<byte> ciphertext, Span<byte> tag)
	{
		Span<byte> buffer = stackalloc byte[Poly1305.KeySize];
		chacha20.Update(Init, buffer);
		using Poly1305 poly1305 = new(buffer);

		poly1305.Update(associatedData);
		poly1305.Update(ciphertext);

		Span<byte> block = stackalloc byte[Poly1305.BlockSize];
		BinaryPrimitives.WriteUInt64LittleEndian(block, (ulong)associatedData.Length);
		BinaryPrimitives.WriteUInt64LittleEndian(block.Slice(8), (ulong)ciphertext.Length);
		poly1305.Update(block);

		poly1305.GetMac(tag);
	}
}
