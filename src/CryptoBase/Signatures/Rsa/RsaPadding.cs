using CryptoBase.Hashes;
using CryptoBase.Hashes.Sha2;
using CryptoBase.Platform;

namespace CryptoBase.Signatures.Rsa;

// The encodings of RFC 8017 for signatures: EMSA-PKCS1-v1_5 (Sec. 9.2) and EMSA-PSS with MGF1 (Sec. 9.1, Appendix B.2.1). An encoded message spans the k bytes of the modulus, the input of RSASP1 and the output of
// RSAVP1. Everything here is public: the message, its hash, the salt and the encoded message all follow from the signature and the public key.
internal static class RsaPadding
{
	internal const int MaxHashLength = 64;

	// The DER encoding of the DigestInfo of each hash up to the hash value, with NULL parameters (RFC 8017, Sec. 9.2, Note 1).
	internal static ReadOnlySpan<byte> Sha256DigestInfo => [0x30, 0x31, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20];

	internal static ReadOnlySpan<byte> Sha384DigestInfo => [0x30, 0x41, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30];

	internal static ReadOnlySpan<byte> Sha512DigestInfo => [0x30, 0x51, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40];

	// The same without parameters.
	internal static ReadOnlySpan<byte> Sha256DigestInfoWithoutParameters => [0x30, 0x2F, 0x30, 0x0B, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x04, 0x20];

	internal static ReadOnlySpan<byte> Sha384DigestInfoWithoutParameters => [0x30, 0x3F, 0x30, 0x0B, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x04, 0x30];

	internal static ReadOnlySpan<byte> Sha512DigestInfoWithoutParameters => [0x30, 0x4F, 0x30, 0x0B, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x04, 0x40];

	// emLen = ⌈(modBits − 1)/8⌉ (RFC 8017, Sec. 8.1.1, step 1), one byte short of k where modBits − 1 is a multiple of 8.
	internal static int GetPssEncodedLength(int modulusBits)
	{
		return (modulusBits + 6) / 8;
	}

	// destination is at least the hash long.
	internal static void Hash<THash>(ReadOnlySpan<byte> source, Span<byte> destination) where THash : unmanaged, IHashCore<THash>
	{
		if (typeof(THash) == typeof(Sha256Core) && PlatformSha256.IsPreferredFor(source.Length))
		{
			SHA256.HashData(source, destination);
			return;
		}

		HashAlgorithm<THash>.HashData(source, destination);
	}

	// EMSA-PKCS1-v1_5-ENCODE (RFC 8017, Sec. 9.2): EM = 0x00 ‖ 0x01 ‖ PS ‖ 0x00 ‖ T, where T is digestInfo followed by hash and encoded has k ≥ tLen + 11 bytes.
	internal static void EncodePkcs1(ReadOnlySpan<byte> digestInfo, ReadOnlySpan<byte> hash, Span<byte> encoded)
	{
		int separator = encoded.Length - digestInfo.Length - hash.Length - 1;
		Debug.Assert(separator >= 10);

		encoded[0] = 0x00;
		encoded[1] = 0x01;
		encoded.Slice(2, separator - 2).Fill(0xFF);
		encoded[separator] = 0x00;
		digestInfo.CopyTo(encoded.Slice(separator + 1));
		hash.CopyTo(encoded.Slice(encoded.Length - hash.Length));
	}

	// Whether encoded is EMSA-PKCS1-v1_5-ENCODE of hash with digestInfo, compared byte for byte (RFC 8017, Sec. 8.2.2, step 4): the lengths of PS and T follow from k and the hash, so nothing is parsed.
	internal static bool IsPkcs1Encoding(ReadOnlySpan<byte> encoded, ReadOnlySpan<byte> digestInfo, ReadOnlySpan<byte> hash)
	{
		int separator = encoded.Length - digestInfo.Length - hash.Length - 1;

		return encoded[0] is 0x00
			&& encoded[1] is 0x01
			&& !encoded.Slice(2, separator - 2).ContainsAnyExcept((byte)0xFF)
			&& encoded[separator] is 0x00
			&& encoded.Slice(separator + 1, digestInfo.Length).SequenceEqual(digestInfo)
			&& encoded.Slice(encoded.Length - hash.Length).SequenceEqual(hash);
	}

	// EMSA-PSS-ENCODE (RFC 8017, Sec. 9.1.1) of mHash with MGF1, both with THash, and salt, for emBits = modBits − 1: EM fills the last emLen bytes of encoded, after a zero byte where emLen = k − 1.
	// The caller has checked that emLen ≥ hLen + sLen + 2 (step 3).
	[SkipLocalsInit]
	internal static void EncodePss<THash>(ReadOnlySpan<byte> mHash, ReadOnlySpan<byte> salt, int modulusBits, Span<byte> encoded) where THash : unmanaged, IHashCore<THash>
	{
		int hashLength = THash.HashLength;
		int emBits = modulusBits - 1;
		Span<byte> em = encoded.Slice(encoded.Length - GetPssEncodedLength(modulusBits));
		Debug.Assert(em.Length >= hashLength + salt.Length + 2);

		encoded.Slice(0, encoded.Length - em.Length).Clear();

		// Steps 5 and 6: H = Hash(0x00 × 8 ‖ mHash ‖ salt), in its place in EM.
		Span<byte> db = em.Slice(0, em.Length - hashLength - 1);
		Span<byte> h = em.Slice(db.Length, hashLength);
		HashPrefixed<THash>(mHash, salt, h);

		// Steps 7 and 8: DB = PS ‖ 0x01 ‖ salt.
		int paddingLength = db.Length - salt.Length - 1;
		db.Slice(0, paddingLength).Clear();
		db[paddingLength] = 0x01;
		salt.CopyTo(db.Slice(paddingLength + 1));

		// Steps 9 to 12.
		Mgf1Xor<THash>(h, db);
		db[0] &= (byte)(0xFF >> 8 * em.Length - emBits);
		em[^1] = 0xBC;
	}

	// EMSA-PSS-VERIFY (RFC 8017, Sec. 9.1.2) of mHash with MGF1, both with THash, and sLen = saltLength, for emBits = modBits − 1, on the k bytes that RSAVP1 gives; encoded is changed.
	[SkipLocalsInit]
	internal static bool IsPssEncoding<THash>(ReadOnlySpan<byte> mHash, Span<byte> encoded, int modulusBits, int saltLength) where THash : unmanaged, IHashCore<THash>
	{
		int hashLength = THash.HashLength;
		int emBits = modulusBits - 1;
		int emLength = GetPssEncodedLength(modulusBits);
		int zeroBits = 8 * emLength - emBits;

		// I2OSP into emLen bytes (Sec. 8.1.2, step 2c) fails if a byte before EM is not zero; then step 3.
		if (encoded.Slice(0, encoded.Length - emLength).ContainsAnyExcept((byte)0x00) || emLength < hashLength + saltLength + 2)
		{
			return false;
		}

		Span<byte> em = encoded.Slice(encoded.Length - emLength);

		// Steps 4 to 6.
		Span<byte> db = em.Slice(0, emLength - hashLength - 1);
		ReadOnlySpan<byte> h = em.Slice(db.Length, hashLength);

		if (em[^1] is not 0xBC || db[0] >> 8 - zeroBits is not 0)
		{
			return false;
		}

		// Steps 7 to 9.
		Mgf1Xor<THash>(h, db);
		db[0] &= (byte)(0xFF >> zeroBits);

		// Step 10: PS of emLen − hLen − sLen − 2 zero bytes, then 0x01.
		int paddingLength = db.Length - saltLength - 1;

		if (db.Slice(0, paddingLength).ContainsAnyExcept((byte)0x00) || db[paddingLength] is not 0x01)
		{
			return false;
		}

		// Steps 11 to 14: H' = Hash(0x00 × 8 ‖ mHash ‖ salt).
		Span<byte> expected = stackalloc byte[MaxHashLength].Slice(0, hashLength);
		HashPrefixed<THash>(mHash, db.Slice(db.Length - saltLength), expected);
		return h.SequenceEqual(expected);
	}

	// destination = Hash(0x00 × 8 ‖ mHash ‖ salt), the hash of M' (RFC 8017, Sec. 9.1.1, step 5).
	[SkipLocalsInit]
	private static void HashPrefixed<THash>(ReadOnlySpan<byte> mHash, ReadOnlySpan<byte> salt, Span<byte> destination) where THash : unmanaged, IHashCore<THash>
	{
		const int MaxStackLength = 8 + 2 * MaxHashLength;
		int length = 8 + mHash.Length + salt.Length;
		Span<byte> prefixed = length <= MaxStackLength ? stackalloc byte[MaxStackLength].Slice(0, length) : new byte[length];

		prefixed.Slice(0, 8).Clear();
		mHash.CopyTo(prefixed.Slice(8));
		salt.CopyTo(prefixed.Slice(8 + mHash.Length));
		Hash<THash>(prefixed, destination);
	}

	// destination ^= MGF1(seed, destination.Length) with THash (RFC 8017, Appendix B.2.1); seed is as long as the hash.
	[SkipLocalsInit]
	private static void Mgf1Xor<THash>(ReadOnlySpan<byte> seed, Span<byte> destination) where THash : unmanaged, IHashCore<THash>
	{
		int hashLength = THash.HashLength;
		Span<byte> input = stackalloc byte[MaxHashLength + 4].Slice(0, seed.Length + 4);
		Span<byte> mask = stackalloc byte[MaxHashLength].Slice(0, hashLength);
		seed.CopyTo(input);

		for (uint counter = 0; !destination.IsEmpty; ++counter)
		{
			BinaryPrimitives.WriteUInt32BigEndian(input.Slice(seed.Length), counter);
			Hash<THash>(input, mask);

			int length = Math.Min(hashLength, destination.Length);
			FastUtils.Xor(mask, destination, destination, length);
			destination = destination.Slice(length);
		}
	}
}
