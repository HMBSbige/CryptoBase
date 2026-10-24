using CryptoBase.Macs.Hmac;

namespace CryptoBase.Kdf;

/// <summary>
/// Implements the TLS 1.2 pseudorandom function as specified by RFC 5246, section 5.
/// </summary>
/// <remarks>
/// The output is <c>P_hash(secret, label || seed)</c> truncated to the output length, with the hash that the cipher suite selects. Any input may overlap the output.
/// </remarks>
public static class Tls12Prf
{
	/// <summary>
	/// Derives key material using the TLS 1.2 PRF.
	/// </summary>
	/// <typeparam name="TCore">The hash core that P_hash uses.</typeparam>
	/// <param name="secret">The secret. It may be empty.</param>
	/// <param name="label">The ASCII label, such as <c>"master secret"u8</c>, without a length prefix or a trailing null.</param>
	/// <param name="seed">The seed.</param>
	/// <param name="output">The buffer that receives the derived key material. Its length selects how many bytes are derived.</param>
	/// <exception cref="ArgumentOutOfRangeException"><paramref name="output" /> is empty.</exception>
	public static void DeriveKey<TCore>(ReadOnlySpan<byte> secret, ReadOnlySpan<byte> label, ReadOnlySpan<byte> seed, Span<byte> output) where TCore : unmanaged, IHmacHashCore<TCore>
	{
		DeriveKey<TCore>(secret, label, seed, ReadOnlySpan<byte>.Empty, output);
	}

	/// <summary>
	/// Derives key material using the TLS 1.2 PRF with the seed <c>seed1 || seed2</c>, such as <c>client_random || server_random</c>.
	/// </summary>
	/// <typeparam name="TCore">The hash core that P_hash uses.</typeparam>
	/// <param name="secret">The secret. It may be empty.</param>
	/// <param name="label">The ASCII label, such as <c>"master secret"u8</c>, without a length prefix or a trailing null.</param>
	/// <param name="seed1">The first part of the seed.</param>
	/// <param name="seed2">The second part of the seed.</param>
	/// <param name="output">The buffer that receives the derived key material. Its length selects how many bytes are derived.</param>
	/// <exception cref="ArgumentOutOfRangeException"><paramref name="output" /> is empty.</exception>
	public static void DeriveKey<TCore>(ReadOnlySpan<byte> secret, ReadOnlySpan<byte> label, ReadOnlySpan<byte> seed1, ReadOnlySpan<byte> seed2, Span<byte> output) where TCore : unmanaged, IHmacHashCore<TCore>
	{
		ArgumentOutOfRangeException.ThrowIfZero(output.Length, nameof(output));

		// Only the label and seed need copying: the secret is consumed before the first write, and a single-block output is written after the last read.
		if (output.Length > TCore.HashLength && (label.Overlaps(output) || seed1.Overlaps(output) || seed2.Overlaps(output)))
		{
			DeriveOverlapping<TCore>(secret, label, seed1, seed2, output);
			return;
		}

		DeriveBlocks<TCore>(secret, label, seed1, seed2, output);
	}

	[SkipLocalsInit]
	private static void DeriveOverlapping<TCore>(ReadOnlySpan<byte> secret, ReadOnlySpan<byte> label, ReadOnlySpan<byte> seed1, ReadOnlySpan<byte> seed2, Span<byte> output) where TCore : unmanaged, IHmacHashCore<TCore>
	{
		int length = checked(label.Length + seed1.Length + seed2.Length);
		using CryptoBuffer<byte> labelAndSeedBuffer = CryptoBuffer<byte>.ShouldUsePool(length) ? new CryptoBuffer<byte>(length) : new CryptoBuffer<byte>(stackalloc byte[length]);
		Span<byte> labelAndSeed = labelAndSeedBuffer.Span;
		label.CopyTo(labelAndSeed);
		seed1.CopyTo(labelAndSeed.Slice(label.Length));
		seed2.CopyTo(labelAndSeed.Slice(label.Length + seed1.Length));
		DeriveBlocks<TCore>(secret, labelAndSeed, ReadOnlySpan<byte>.Empty, ReadOnlySpan<byte>.Empty, output);
	}

	[SkipLocalsInit]
	private static void DeriveBlocks<TCore>(ReadOnlySpan<byte> secret, ReadOnlySpan<byte> label, ReadOnlySpan<byte> seed1, ReadOnlySpan<byte> seed2, Span<byte> output) where TCore : unmanaged, IHmacHashCore<TCore>
	{
		int hashLength = TCore.HashLength;
		using CryptoBuffer<byte> aBuffer = new(stackalloc byte[hashLength]);
		Span<byte> a = aBuffer.Span;
		Span<byte> remainingOutput = output;
		Unsafe.SkipInit(out HmacState<TCore> hmac);

		try
		{
			// Every output needs at least two MACs, A(1) and one block, so the key seeds are always reused.
			hmac.Initialize(secret, true);

			// A(1) = HMAC(secret, label || seed)
			hmac.Append(label);
			hmac.Append(seed1);
			hmac.Append(seed2);
			hmac.GetMacAndResetDestructive(a);

			while (remainingOutput.Length > hashLength)
			{
				hmac.Append(a);
				hmac.Append(label);
				hmac.Append(seed1);
				hmac.Append(seed2);
				hmac.GetMacAndResetDestructive(remainingOutput.Slice(0, hashLength));
				remainingOutput = remainingOutput.Slice(hashLength);

				// A(i + 1) = HMAC(secret, A(i))
				hmac.Append(a);
				hmac.GetMacAndResetDestructive(a);
			}

			hmac.Append(a);
			hmac.Append(label);
			hmac.Append(seed1);
			hmac.Append(seed2);

			if (remainingOutput.Length == hashLength)
			{
				hmac.GetMacDestructive(remainingOutput);
				return;
			}

			// A(n) is no longer needed, so the truncated last block reuses its buffer.
			hmac.GetMacDestructive(a);
			a.Slice(0, remainingOutput.Length).CopyTo(remainingOutput);
		}
		finally
		{
			hmac.ZeroMemory();
		}
	}
}
