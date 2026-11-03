namespace CryptoBase.Signatures.Rsa;

// The RSA signature algorithms, RsaPkcs1Sha256 to RsaPssSha512, as sets of bits of their values.
internal static class RsaAlgorithms
{
	internal const int Pkcs1 = 1 << (int)SignatureAlgorithm.RsaPkcs1Sha256 | 1 << (int)SignatureAlgorithm.RsaPkcs1Sha384 | 1 << (int)SignatureAlgorithm.RsaPkcs1Sha512;
	internal const int Pss = 1 << (int)SignatureAlgorithm.RsaPssSha256 | 1 << (int)SignatureAlgorithm.RsaPssSha384 | 1 << (int)SignatureAlgorithm.RsaPssSha512;
	internal const int All = Pkcs1 | Pss;

	// The bit of an RSA algorithm, or 0 for any other value.
	internal static int Bit(SignatureAlgorithm algorithm)
	{
		return algorithm is >= SignatureAlgorithm.RsaPkcs1Sha256 and <= SignatureAlgorithm.RsaPssSha512 ? 1 << (int)algorithm : 0;
	}

	internal static bool IsPss(SignatureAlgorithm algorithm)
	{
		return (Bit(algorithm) & Pss) is not 0;
	}

	// Of an RSA algorithm.
	internal static int HashLength(SignatureAlgorithm algorithm)
	{
		return algorithm switch
		{
			SignatureAlgorithm.RsaPkcs1Sha256 or SignatureAlgorithm.RsaPssSha256 => 32,
			SignatureAlgorithm.RsaPkcs1Sha384 or SignatureAlgorithm.RsaPssSha384 => 48,
			_ => 64
		};
	}

	// The algorithms whose encoded message fits the modulus (RFC 8017): EMSA-PSS needs emLen ≥ hLen + sLen + 2 (Sec. 9.1.1, step 3), and EMSA-PKCS1-v1_5 needs k ≥ tLen + 11, where the DigestInfo T has 19
	// bytes before the hash (Sec. 9.2, step 3).
	internal static int Fitting(int modulusBits)
	{
		int encodedLength = RsaPadding.GetPssEncodedLength(modulusBits);
		int modulusLength = (modulusBits + 7) / 8;
		int fitting = 0;

		for (SignatureAlgorithm algorithm = SignatureAlgorithm.RsaPkcs1Sha256; algorithm <= SignatureAlgorithm.RsaPssSha512; ++algorithm)
		{
			int hashLength = HashLength(algorithm);
			bool fits = IsPss(algorithm) ? encodedLength >= 2 * hashLength + 2 : modulusLength >= 19 + hashLength + 11;
			fitting |= fits ? Bit(algorithm) : 0;
		}

		return fitting;
	}
}
