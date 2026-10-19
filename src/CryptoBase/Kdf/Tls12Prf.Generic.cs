using CryptoBase.Abstractions.Macs;

namespace CryptoBase.Kdf;

/// <summary>
/// Implements the TLS 1.2 pseudorandom function as specified by RFC 5246, section 5, over a MAC algorithm.
/// </summary>
/// <remarks>
/// The output is <c>P_hash(secret, label || seed)</c> truncated to the output length, with the HMAC that the cipher suite selects.
/// A single-block output takes two calls to <c>TMac.Mac</c>. A longer output creates one keyed <typeparamref name="TMac" /> instance and computes every
/// block with it. Any input may overlap the output.
/// </remarks>
/// <typeparam name="TMac">The HMAC that P_hash uses.</typeparam>
public static class Tls12Prf<TMac> where TMac : class, IMacAlgorithm<TMac>
{
	/// <summary>
	/// Derives key material using the TLS 1.2 PRF.
	/// </summary>
	/// <param name="secret">The secret. It may be empty.</param>
	/// <param name="label">The ASCII label, such as <c>"master secret"u8</c>, without a length prefix or a trailing null.</param>
	/// <param name="seed">The seed.</param>
	/// <param name="output">The buffer that receives the derived key material. Its length selects how many bytes are derived.</param>
	/// <exception cref="ArgumentOutOfRangeException"><paramref name="output" /> is empty.</exception>
	public static void DeriveKey(ReadOnlySpan<byte> secret, ReadOnlySpan<byte> label, ReadOnlySpan<byte> seed, Span<byte> output)
	{
		DeriveKey(secret, label, seed, ReadOnlySpan<byte>.Empty, output);
	}

	/// <summary>
	/// Derives key material using the TLS 1.2 PRF with the seed <c>seed1 || seed2</c>, such as <c>client_random || server_random</c>.
	/// </summary>
	/// <param name="secret">The secret. It may be empty.</param>
	/// <param name="label">The ASCII label, such as <c>"master secret"u8</c>, without a length prefix or a trailing null.</param>
	/// <param name="seed1">The first part of the seed.</param>
	/// <param name="seed2">The second part of the seed.</param>
	/// <param name="output">The buffer that receives the derived key material. Its length selects how many bytes are derived.</param>
	/// <exception cref="ArgumentOutOfRangeException"><paramref name="output" /> is empty.</exception>
	public static void DeriveKey(ReadOnlySpan<byte> secret, ReadOnlySpan<byte> label, ReadOnlySpan<byte> seed1, ReadOnlySpan<byte> seed2, Span<byte> output)
	{
		ArgumentOutOfRangeException.ThrowIfZero(output.Length, nameof(output));

		// A single block stays one-shot and allocates nothing; the keyed instance is created only when more than one block reuses it.
		if (output.Length <= TMac.MacLength)
		{
			DeriveBlock(secret, label, seed1, seed2, output);
			return;
		}

		DeriveBlocks(secret, label, seed1, seed2, output);
	}

	// A(1) = MAC(secret, label || seed) and the block is MAC(secret, A(1) || label || seed). The label and seed are copied before the output is written, so
	// they may overlap it. The block goes through a scratch buffer when the output is short or overlaps the secret, so no call gets overlapping buffers.
	[SkipLocalsInit]
	private static void DeriveBlock(ReadOnlySpan<byte> secret, ReadOnlySpan<byte> label, ReadOnlySpan<byte> seed1, ReadOnlySpan<byte> seed2, Span<byte> output)
	{
		int macLength = TMac.MacLength;
		int inputLength = checked(macLength + label.Length + seed1.Length + seed2.Length);
		using CryptoBuffer<byte> inputBuffer = CryptoBuffer<byte>.ShouldUsePool(inputLength) ? new CryptoBuffer<byte>(inputLength) : new CryptoBuffer<byte>(stackalloc byte[inputLength]);

		Span<byte> blockInput = inputBuffer.Span;
		Span<byte> labelAndSeed = blockInput.Slice(macLength);
		label.CopyTo(labelAndSeed);
		seed1.CopyTo(labelAndSeed.Slice(label.Length));
		seed2.CopyTo(labelAndSeed.Slice(label.Length + seed1.Length));

		TMac.Mac(secret, labelAndSeed, blockInput.Slice(0, macLength));

		if (output.Length == macLength && !secret.Overlaps(output))
		{
			TMac.Mac(secret, blockInput, output);
			return;
		}

		using CryptoBuffer<byte> block = new(stackalloc byte[macLength]);
		TMac.Mac(secret, blockInput, block.Span);
		block.Span.Slice(0, output.Length).CopyTo(output);
	}

	// A(i) = MAC(secret, A(i - 1)) with A(0) = label || seed, and block i = MAC(secret, A(i) || label || seed). The buffer holds A(i) || label || seed,
	// so no append reads the output and the label and seed may overlap it. Create consumes the secret before the first block is written, so the secret may
	// overlap the output too.
	[SkipLocalsInit]
	private static void DeriveBlocks(ReadOnlySpan<byte> secret, ReadOnlySpan<byte> label, ReadOnlySpan<byte> seed1, ReadOnlySpan<byte> seed2, Span<byte> output)
	{
		int macLength = TMac.MacLength;
		int inputLength = checked(macLength + label.Length + seed1.Length + seed2.Length);
		using CryptoBuffer<byte> inputBuffer = CryptoBuffer<byte>.ShouldUsePool(inputLength) ? new CryptoBuffer<byte>(inputLength) : new CryptoBuffer<byte>(stackalloc byte[inputLength]);
		using CryptoBuffer<byte> lastBlock = new(stackalloc byte[macLength]);

		Span<byte> blockInput = inputBuffer.Span;
		Span<byte> a = blockInput.Slice(0, macLength);
		Span<byte> labelAndSeed = blockInput.Slice(macLength);
		label.CopyTo(labelAndSeed);
		seed1.CopyTo(labelAndSeed.Slice(label.Length));
		seed2.CopyTo(labelAndSeed.Slice(label.Length + seed1.Length));

		using TMac mac = TMac.Create(secret);
		mac.Append(labelAndSeed);
		mac.GetMacAndReset(a);
		Span<byte> remainingOutput = output;

		while (true)
		{
			mac.Append(blockInput);

			if (remainingOutput.Length < macLength)
			{
				mac.GetMacAndReset(lastBlock.Span);
				lastBlock.Span.Slice(0, remainingOutput.Length).CopyTo(remainingOutput);
				return;
			}

			mac.GetMacAndReset(remainingOutput.Slice(0, macLength));
			remainingOutput = remainingOutput.Slice(macLength);

			if (remainingOutput.IsEmpty)
			{
				return;
			}

			// The append consumes A(i) before GetMacAndReset overwrites it with A(i + 1).
			mac.Append(a);
			mac.GetMacAndReset(a);
		}
	}
}
