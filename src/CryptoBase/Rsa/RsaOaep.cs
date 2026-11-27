namespace CryptoBase.Rsa;

// EME-OAEP of RFC 8017 (Sec. 7.1.1, step 2, and Sec. 7.1.2, step 3): THash hashes the label and TMgfHash drives MGF1.
// Both hashes must have 1 to RsaPadding.MaxHashLength bytes, the size of the stack buffers here and in RsaPadding.Mgf1XorSecret.
// An encoded message spans the k bytes of the modulus, the input of RSAEP and the output of RSADP.
// The message, the seed, the masks and the encoded message are secret.
internal static class RsaOaep
{
	// Negative if the modulus is too short for the hash (Sec. 7.1.1, step 1.b).
	internal static int GetMaxMessageLength<THash>(int modulusLength) where THash : unmanaged, IHashCore<THash>
	{
		return modulusLength - 2 * THash.HashLength - 2;
	}

	internal static void Encode<THash, TMgfHash>(ReadOnlySpan<byte> message, ReadOnlySpan<byte> label, ReadOnlySpan<byte> seed, Span<byte> encoded) where THash : unmanaged, IHashCore<THash> where TMgfHash : unmanaged, IHashCore<TMgfHash>
	{
		int hashLength = THash.HashLength;
		Debug.Assert(seed.Length == hashLength && message.Length <= GetMaxMessageLength<THash>(encoded.Length));

		Span<byte> maskedSeed = encoded.Slice(1, hashLength);
		Span<byte> db = encoded.Slice(1 + hashLength);

		// Steps a to c.
		RsaPadding.Hash<THash>(label, db);
		int separator = db.Length - message.Length - 1;
		db.Slice(hashLength, separator - hashLength).Clear();
		db[separator] = 0x01;
		message.CopyTo(db.Slice(separator + 1));

		// Steps d to i.
		seed.CopyTo(maskedSeed);
		RsaPadding.Mgf1XorSecret<TMgfHash>(maskedSeed, db);
		RsaPadding.Mgf1XorSecret<TMgfHash>(db, maskedSeed);
		encoded[0] = 0x00;
	}

	// Whether encoded is an encoding with the label; if so, M is encoded[start..], and otherwise start is meaningless.
	// encoded is unmasked in place into Y ‖ seed ‖ DB.
	// Every check runs and none branches on or indexes by the encoded message, as Manger's attack learns from telling the failures apart (Sec. 7.1.2, note).
	internal static bool Decode<THash, TMgfHash>(Span<byte> encoded, ReadOnlySpan<byte> label, out int start) where THash : unmanaged, IHashCore<THash> where TMgfHash : unmanaged, IHashCore<TMgfHash>
	{
		int hashLength = THash.HashLength;
		Debug.Assert(encoded.Length >= 2 * hashLength + 2);

		Span<byte> seed = encoded.Slice(1, hashLength);
		Span<byte> db = encoded.Slice(1 + hashLength);

		// Steps b to f.
		RsaPadding.Mgf1XorSecret<TMgfHash>(db, seed);
		RsaPadding.Mgf1XorSecret<TMgfHash>(seed, db);

		// Steps a and g: Y = 0 and lHash' = lHash.
		Span<byte> difference = stackalloc byte[RsaPadding.MaxHashLength].Slice(0, hashLength);
		RsaPadding.Hash<THash>(label, difference);
		FastUtils.Xor(db, difference, difference, hashLength);
		ulong invalid = encoded[0] | FixedTime.Accumulate(difference);
		difference.ZeroMemory();

		// Step g: PS is zero bytes up to the first 0x01; another byte before it, or no 0x01, is invalid.
		// searching stays all ones up to the first nonzero byte, so separator and misplaced take that byte alone.
		ReadOnlySpan<byte> rest = db.Slice(hashLength);
		int searching = -1;
		int misplaced = 0;
		int separator = 0;

		for (int i = 0; i < rest.Length; ++i)
		{
			int value = rest[i];
			int isZero = value - 1 >> 31;
			int isOne = (value ^ 1) - 1 >> 31;
			separator |= i & searching & isOne;
			misplaced |= searching & ~(isZero | isOne);
			searching &= isZero;
		}

		invalid |= (uint)(searching | misplaced);
		start = encoded.Length - rest.Length + separator + 1;
		return invalid is 0;
	}
}
