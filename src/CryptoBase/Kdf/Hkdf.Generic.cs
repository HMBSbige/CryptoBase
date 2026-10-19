using CryptoBase.Abstractions.Macs;

namespace CryptoBase.Kdf;

/// <summary>
/// Implements HKDF as specified by RFC 5869 over a MAC algorithm.
/// </summary>
/// <remarks>
/// Extract and a single-block expansion take one call to <c>TMac.Mac</c> each. A longer expansion creates one keyed <typeparamref name="TMac" /> instance and
/// computes every block with it. Any input may overlap the output.
/// </remarks>
/// <typeparam name="TMac">The MAC algorithm, normally an HMAC.</typeparam>
public static class Hkdf<TMac> where TMac : class, IMacAlgorithm<TMac>
{
	/// <summary>
	/// Extracts a pseudorandom key using HKDF.
	/// </summary>
	/// <param name="ikm">The input key material.</param>
	/// <param name="salt">The salt. It may be empty.</param>
	/// <param name="prk">The buffer that receives the pseudorandom key.</param>
	/// <returns>The number of bytes written to <paramref name="prk" />.</returns>
	/// <exception cref="ArgumentOutOfRangeException"><paramref name="prk" /> is shorter than the MAC.</exception>
	public static int Extract(ReadOnlySpan<byte> ikm, ReadOnlySpan<byte> salt, Span<byte> prk)
	{
		ArgumentOutOfRangeException.ThrowIfLessThan(prk.Length, TMac.MacLength, nameof(prk));

		if (ikm.Overlaps(prk) || salt.Overlaps(prk))
		{
			return ExtractOverlapping(ikm, salt, prk);
		}

		return TMac.Mac(salt, ikm, prk);
	}

	/// <summary>
	/// Expands a pseudorandom key using HKDF.
	/// </summary>
	/// <param name="prk">The pseudorandom key, at least as long as the MAC.</param>
	/// <param name="output">The buffer that receives the output key material. Its length selects how many bytes are derived.</param>
	/// <param name="info">The context and application-specific information. It may be empty.</param>
	/// <exception cref="ArgumentOutOfRangeException">
	/// <paramref name="output" /> is empty or longer than 255 MACs, or <paramref name="prk" /> is shorter than the MAC.
	/// </exception>
	public static void Expand(ReadOnlySpan<byte> prk, Span<byte> output, ReadOnlySpan<byte> info)
	{
		ValidateOutputLength(output);
		ArgumentOutOfRangeException.ThrowIfLessThan(prk.Length, TMac.MacLength, nameof(prk));

		ExpandCore(prk, output, info);
	}

	/// <summary>
	/// Derives key material using HKDF extract-and-expand.
	/// </summary>
	/// <param name="ikm">The input key material.</param>
	/// <param name="output">The buffer that receives the output key material. Its length selects how many bytes are derived.</param>
	/// <param name="salt">The salt. It may be empty.</param>
	/// <param name="info">The context and application-specific information. It may be empty.</param>
	/// <exception cref="ArgumentOutOfRangeException"><paramref name="output" /> is empty or longer than 255 MACs.</exception>
	[SkipLocalsInit]
	public static void DeriveKey(ReadOnlySpan<byte> ikm, Span<byte> output, ReadOnlySpan<byte> salt, ReadOnlySpan<byte> info)
	{
		ValidateOutputLength(output);

		using CryptoBuffer<byte> prk = new(stackalloc byte[TMac.MacLength]);
		TMac.Mac(salt, ikm, prk.Span);
		ExpandCore(prk.Span, output, info);
	}

	private static void ValidateOutputLength(Span<byte> output)
	{
		ArgumentOutOfRangeException.ThrowIfZero(output.Length, nameof(output));

		int maxOkmLength = checked(255 * TMac.MacLength);
		ArgumentOutOfRangeException.ThrowIfGreaterThan(output.Length, maxOkmLength, nameof(output));
	}

	[SkipLocalsInit]
	private static int ExtractOverlapping(ReadOnlySpan<byte> ikm, ReadOnlySpan<byte> salt, Span<byte> prk)
	{
		int macLength = TMac.MacLength;
		using CryptoBuffer<byte> mac = new(stackalloc byte[macLength]);
		TMac.Mac(salt, ikm, mac.Span);
		mac.Span.CopyTo(prk);
		return macLength;
	}

	private static void ExpandCore(ReadOnlySpan<byte> prk, Span<byte> output, ReadOnlySpan<byte> info)
	{
		// A single block stays one-shot and allocates nothing; the keyed instance is created only when more than one block reuses it.
		if (output.Length <= TMac.MacLength)
		{
			ExpandBlock(prk, output, info);
			return;
		}

		ExpandBlocks(prk, output, info);
	}

	// T(1) = MAC(PRK, info || 1). Info is copied before the output is written, so it may overlap the output. The MAC goes through a scratch buffer when
	// the output is short or overlaps the key, so the call never gets overlapping buffers.
	[SkipLocalsInit]
	private static void ExpandBlock(ReadOnlySpan<byte> prk, Span<byte> output, ReadOnlySpan<byte> info)
	{
		int macLength = TMac.MacLength;
		int inputLength = checked(info.Length + 1);
		using CryptoBuffer<byte> inputBuffer = CryptoBuffer<byte>.ShouldUsePool(inputLength) ? new CryptoBuffer<byte>(inputLength) : new CryptoBuffer<byte>(stackalloc byte[inputLength]);

		Span<byte> input = inputBuffer.Span;
		info.CopyTo(input);
		input[^1] = 1;

		if (output.Length == macLength && !prk.Overlaps(output))
		{
			TMac.Mac(prk, input, output);
			return;
		}

		using CryptoBuffer<byte> block = new(stackalloc byte[macLength]);
		TMac.Mac(prk, input, block.Span);
		block.Span.Slice(0, output.Length).CopyTo(output);
	}

	// T(i) = MAC(PRK, T(i - 1) || info || i), with T(0) empty. The buffer holds T(i - 1) || info || i and the first block skips T(0), so no append reads
	// the output and info may overlap it. Create consumes the key before the first block is written, so the key may overlap the output too.
	[SkipLocalsInit]
	private static void ExpandBlocks(ReadOnlySpan<byte> prk, Span<byte> output, ReadOnlySpan<byte> info)
	{
		int macLength = TMac.MacLength;
		int inputLength = checked(macLength + info.Length + 1);
		using CryptoBuffer<byte> inputBuffer = CryptoBuffer<byte>.ShouldUsePool(inputLength) ? new CryptoBuffer<byte>(inputLength) : new CryptoBuffer<byte>(stackalloc byte[inputLength]);
		using CryptoBuffer<byte> lastBlock = new(stackalloc byte[macLength]);

		Span<byte> blockInput = inputBuffer.Span;
		Span<byte> previous = blockInput.Slice(0, macLength);
		info.CopyTo(blockInput.Slice(macLength));

		using TMac mac = TMac.Create(prk);
		ReadOnlySpan<byte> input = blockInput.Slice(macLength);
		Span<byte> remainingOutput = output;
		byte counter = 0;

		while (true)
		{
			blockInput[^1] = ++counter;
			mac.Append(input);

			if (remainingOutput.Length < macLength)
			{
				mac.GetMacAndReset(lastBlock.Span);
				lastBlock.Span.Slice(0, remainingOutput.Length).CopyTo(remainingOutput);
				return;
			}

			Span<byte> block = remainingOutput.Slice(0, macLength);
			mac.GetMacAndReset(block);
			remainingOutput = remainingOutput.Slice(macLength);

			if (remainingOutput.IsEmpty)
			{
				return;
			}

			block.CopyTo(previous);
			input = blockInput;
		}
	}
}
