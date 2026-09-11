namespace CryptoBase.Ciphers.Padding;

/// <summary>
/// Calculates padding lengths, applies padding, and validates padding for symmetric block ciphers.
/// </summary>
public static class SymmetricPadding
{
	/// <summary>
	/// Calculates the padded input length in bytes for the selected padding mode.
	/// </summary>
	/// <param name="sourceLength">The nonnegative input length in bytes.</param>
	/// <param name="blockSizeInBytes">The block size, from 1 to 255 bytes.</param>
	/// <param name="paddingMode">The padding mode.</param>
	/// <returns>The padded length in bytes.</returns>
	/// <remarks>
	/// <para>
	/// <see cref="PaddingMode.None"/> requires a whole number of blocks and returns <paramref name="sourceLength"/> unchanged.
	/// <see cref="PaddingMode.Zeros"/> rounds up to a whole block, leaving aligned input unchanged.
	/// Both modes return zero for empty input.
	/// </para>
	/// <para>
	/// <see cref="PaddingMode.PKCS7"/>, <see cref="PaddingMode.ANSIX923"/>, and <see cref="PaddingMode.ISO10126"/>
	/// add 1 to <paramref name="blockSizeInBytes"/> bytes. Input that already contains a whole number of blocks,
	/// including empty input, receives a full block of padding.
	/// </para>
	/// </remarks>
	/// <exception cref="ArgumentOutOfRangeException">
	/// <paramref name="sourceLength"/> is negative, <paramref name="blockSizeInBytes"/> is outside 1 to 255,
	/// or <paramref name="paddingMode"/> is unsupported.
	/// </exception>
	/// <exception cref="ArgumentException"><see cref="PaddingMode.None"/> is selected and the input length is not a multiple of the block size.</exception>
	/// <exception cref="OverflowException">The result exceeds <see cref="int.MaxValue"/>.</exception>
	public static int GetPaddedLength(int sourceLength, int blockSizeInBytes, PaddingMode paddingMode)
	{
		ArgumentOutOfRangeException.ThrowIfNegative(sourceLength);
		ValidateParameters(blockSizeInBytes, paddingMode);

		int remainder = sourceLength % blockSizeInBytes;

		switch (paddingMode)
		{
			case PaddingMode.None when remainder is not 0:
			{
				throw new ArgumentException("Input must contain whole blocks when padding is disabled.", nameof(sourceLength));
			}
			case PaddingMode.None:
			case PaddingMode.Zeros when remainder is 0:
			{
				return sourceLength;
			}
			default:
			{
				int paddingLength = blockSizeInBytes - remainder;
				return checked(sourceLength + paddingLength);
			}
		}
	}

	/// <summary>
	/// Copies the input to the destination and appends any padding required by the selected mode.
	/// </summary>
	/// <param name="source">The unpadded input.</param>
	/// <param name="destination">The output buffer, with capacity for the length returned by <see cref="GetPaddedLength"/>.</param>
	/// <param name="blockSizeInBytes">The block size, from 1 to 255 bytes.</param>
	/// <param name="paddingMode">The padding mode.</param>
	/// <returns>The number of bytes written, including padding.</returns>
	/// <remarks>
	/// <para>
	/// In-place padding is supported when <paramref name="source"/> and <paramref name="destination"/> start at the same address.
	/// Otherwise, <paramref name="source"/> must not overlap the portion of <paramref name="destination"/> being written.
	/// Destination bytes beyond the returned length remain unchanged.
	/// </para>
	/// <para>
	/// Invalid arguments leave the destination unchanged; a failure to generate
	/// <see cref="PaddingMode.ISO10126"/> random bytes may modify the padding region.
	/// </para>
	/// </remarks>
	/// <exception cref="ArgumentException">Input is unaligned with <see cref="PaddingMode.None"/>, the destination is too short, or input and written output overlap at different starting addresses.</exception>
	/// <exception cref="ArgumentOutOfRangeException">The block size or padding mode is invalid.</exception>
	/// <exception cref="OverflowException">The padded length exceeds <see cref="int.MaxValue"/>.</exception>
	/// <exception cref="CryptographicException">Random bytes could not be generated for <see cref="PaddingMode.ISO10126"/>.</exception>
	public static int Pad(scoped ReadOnlySpan<byte> source, scoped Span<byte> destination, int blockSizeInBytes, PaddingMode paddingMode)
	{
		int paddedLength = GetPaddedLength(source.Length, blockSizeInBytes, paddingMode);

		if (destination.Length < paddedLength)
		{
			throw new ArgumentException("Destination is too short for the padded input.", nameof(destination));
		}

		Span<byte> output = destination.Slice(0, paddedLength);

		if (source.Overlaps(output, out int offset) && offset is not 0)
		{
			throw new ArgumentException("Input and output must be disjoint or start at the same address.", nameof(destination));
		}

		Span<byte> padding = output.Slice(source.Length);
		int paddingLength = padding.Length;

		switch (paddingMode)
		{
			case PaddingMode.PKCS7:
			{
				padding.Fill((byte)paddingLength);
				break;
			}
			case PaddingMode.ANSIX923:
			{
				padding.Slice(0, paddingLength - 1).Clear();
				padding[paddingLength - 1] = (byte)paddingLength;
				break;
			}
			case PaddingMode.ISO10126:
			{
				RandomNumberGenerator.Fill(padding.Slice(0, paddingLength - 1));
				padding[paddingLength - 1] = (byte)paddingLength;
				break;
			}
			case PaddingMode.Zeros:
			{
				padding.Clear();
				break;
			}
		}

		source.CopyTo(output);
		return paddedLength;
	}

	/// <summary>
	/// Validates padding and returns the length to retain without modifying the input.
	/// </summary>
	/// <param name="source">The input to check. May contain the whole message or only its final block.</param>
	/// <param name="blockSizeInBytes">The block size, from 1 to 255 bytes.</param>
	/// <param name="paddingMode">The padding mode.</param>
	/// <param name="unpaddedLength">The number of bytes to retain from <paramref name="source"/>, or zero when this method returns <see langword="false"/>.</param>
	/// <returns><see langword="true"/> if the input satisfies the selected padding rules; otherwise, <see langword="false"/>.</returns>
	/// <remarks>
	/// <para>
	/// All modes reject input whose length is not a multiple of <paramref name="blockSizeInBytes"/>.
	/// When only the final block is supplied, <paramref name="unpaddedLength"/> refers to that block, not the whole message.
	/// </para>
	/// <para>
	/// <see cref="PaddingMode.None"/> and <see cref="PaddingMode.Zeros"/> check only alignment and retain the entire input,
	/// including empty input. Trailing zeros are not removed because they may belong to the original data.
	/// </para>
	/// <para>
	/// <see cref="PaddingMode.PKCS7"/>, <see cref="PaddingMode.ANSIX923"/>, and <see cref="PaddingMode.ISO10126"/>
	/// require nonempty input whose final byte specifies a padding length from 1 to <paramref name="blockSizeInBytes"/>.
	/// Preceding padding bytes must equal that length for PKCS7 or zero for ANSI X9.23; ISO10126 accepts any values.
	/// </para>
	/// </remarks>
	/// <exception cref="ArgumentOutOfRangeException">The block size or padding mode is invalid.</exception>
	public static bool TryGetUnpaddedLength(scoped ReadOnlySpan<byte> source, int blockSizeInBytes, PaddingMode paddingMode, out int unpaddedLength)
	{
		ValidateParameters(blockSizeInBytes, paddingMode);
		unpaddedLength = 0;

		if (source.Length % blockSizeInBytes is not 0)
		{
			return false;
		}

		if (paddingMode is PaddingMode.None or PaddingMode.Zeros)
		{
			unpaddedLength = source.Length;
			return true;
		}

		if (source.IsEmpty)
		{
			return false;
		}

		ReadOnlySpan<byte> finalBlock = source.Slice(source.Length - blockSizeInBytes);
		int count = finalBlock[blockSizeInBytes - 1];
		int invalid = count - 1 >> 31 | blockSizeInBytes - count >> 31;

		// Scan the rest of the final block without early exit; mask out non-padding bytes.
		if (paddingMode is PaddingMode.PKCS7 or PaddingMode.ANSIX923)
		{
			int expected = paddingMode is PaddingMode.PKCS7 ? count : 0;

			for (int i = 1; i < blockSizeInBytes; ++i)
			{
				int mask = i - count >> 31;
				invalid |= (finalBlock[blockSizeInBytes - 1 - i] ^ expected) & mask;
			}
		}

		if (invalid is not 0)
		{
			return false;
		}

		unpaddedLength = source.Length - count;
		return true;
	}

	private static void ValidateParameters(int blockSizeInBytes, PaddingMode paddingMode)
	{
		ArgumentOutOfRangeException.ThrowIfLessThan(blockSizeInBytes, 1);
		ArgumentOutOfRangeException.ThrowIfGreaterThan(blockSizeInBytes, byte.MaxValue);

		if (paddingMode is not (PaddingMode.None or PaddingMode.Zeros or PaddingMode.PKCS7 or PaddingMode.ANSIX923 or PaddingMode.ISO10126))
		{
			throw new ArgumentOutOfRangeException(nameof(paddingMode));
		}
	}
}
