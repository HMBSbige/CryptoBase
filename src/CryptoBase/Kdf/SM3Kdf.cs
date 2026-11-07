namespace CryptoBase.Kdf;

/// <summary>
/// Implements the key derivation function with SM3 that SM2 and SM9 use, as specified by GB/T 32918.4-2016, section 5.4.3.
/// </summary>
/// <remarks>
/// The output is <c>SM3(Z || ct)</c> for the 32-bit big-endian counters <c>ct</c> = 1, 2, … in turn, concatenated and truncated to the output length, where <c>Z</c> is the secret. The secret may overlap the output.
/// </remarks>
public static class SM3Kdf
{
	/// <summary>
	/// Derives key material using the SM3 key derivation function.
	/// </summary>
	/// <param name="secret">The secret <c>Z</c>. It may be empty.</param>
	/// <param name="output">The buffer that receives the derived key material. Its length selects how many bytes are derived.</param>
	/// <exception cref="ArgumentOutOfRangeException"><paramref name="output" /> is empty.</exception>
	[SkipLocalsInit]
	public static void DeriveKey(ReadOnlySpan<byte> secret, Span<byte> output)
	{
		ArgumentOutOfRangeException.ThrowIfZero(output.Length, nameof(output));

		// The state takes all of the secret before the first byte of output is written.
		Unsafe.SkipInit(out SM3KdfState kdf);
		kdf.Initialize();
		kdf.Append(secret);
		kdf.Derive(output);
		kdf.Clear();
	}
}
