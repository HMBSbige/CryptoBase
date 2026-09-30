namespace CryptoBase.Ciphers.Modes.Ctr;

// Counters use little-endian byte order after reversing the external big-endian block.
internal interface ICtrIncrementer
{
	static abstract bool CarriesBeyond32 { get; }

	static abstract Vector128<byte> Inc(Vector128<byte> counter);

	static abstract Vector256<byte> Add01(Vector256<byte> counter);

	static abstract Vector256<byte> Add22(Vector256<byte> counter);

	static abstract Vector512<byte> Add0123(Vector512<byte> counter);

	static abstract Vector512<byte> Add4444(Vector512<byte> counter);
}
