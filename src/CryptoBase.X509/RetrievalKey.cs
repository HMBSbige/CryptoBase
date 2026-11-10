using System.Buffers;
using System.Buffers.Binary;
using System.Runtime.InteropServices;

namespace CryptoBase.X509;

// The key of what a URI gives the certificates of one issuer, in a validation and in the caches: another CA can name the same URI, and what it was answered must not stand in for what the certificates of this issuer find there.
// It is the SHA-256 digest of the digest of the issuer's name followed by the URI, so that its size depends on neither, as the peer chooses both; the digest of the name, of fixed length, keeps the two apart, and a collision, which would let one CA's answer stand for another's, is as hard to find as one of SHA-256.
internal readonly record struct RetrievalKey(UInt128 First, UInt128 Second)
{
	// Most URIs fit, as UTF-16, after the digest of the name.
	private const int MaxStackInput = 512;

	private RetrievalKey(ReadOnlySpan<byte> digest) : this(BinaryPrimitives.ReadUInt128LittleEndian(digest), BinaryPrimitives.ReadUInt128LittleEndian(digest.Slice(16)))
	{
	}

	// The digest of an issuer's name, which the keys of the URIs that one certificate names share.
	public static byte[] DigestIssuer(ReadOnlySpan<byte> issuer)
	{
		return SHA256.HashData(issuer);
	}

	public static RetrievalKey Create(ReadOnlySpan<byte> issuerDigest, Uri uri)
	{
		Debug.Assert(issuerDigest.Length == SHA256.HashSizeInBytes);

		ReadOnlySpan<byte> text = MemoryMarshal.AsBytes(uri.AbsoluteUri.AsSpan());
		int length = issuerDigest.Length + text.Length;
		byte[]? rented = null;
		Span<byte> input = length <= MaxStackInput ? stackalloc byte[MaxStackInput] : rented = ArrayPool<byte>.Shared.Rent(length);

		try
		{
			issuerDigest.CopyTo(input);
			text.CopyTo(input.Slice(issuerDigest.Length));
			Span<byte> digest = stackalloc byte[SHA256.HashSizeInBytes];
			SHA256.HashData(input.Slice(0, length), digest);
			return new RetrievalKey(digest);
		}
		finally
		{
			if (rented is not null)
			{
				ArrayPool<byte>.Shared.Return(rented);
			}
		}
	}
}
