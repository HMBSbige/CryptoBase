using CryptoBase.Macs.Hmac;

namespace CryptoBase.Kdf;

/// <summary>
/// Implements HKDF as specified by RFC 5869.
/// </summary>
public static class Hkdf
{
	/// <summary>
	/// Extracts a pseudorandom key using HKDF.
	/// </summary>
	/// <returns>The number of bytes written to <paramref name="prk" />.</returns>
	public static int Extract<THash>(ReadOnlySpan<byte> ikm, ReadOnlySpan<byte> salt, Span<byte> prk) where THash : unmanaged, IHmacHashCore<THash>
	{
		ValidateExtractArguments<THash>(prk);

		return HmacAlgorithm<THash>.Mac(salt, ikm, prk);
	}

	/// <summary>
	/// Expands a pseudorandom key using HKDF.
	/// </summary>
	public static void Expand<THash>(ReadOnlySpan<byte> prk, Span<byte> output, ReadOnlySpan<byte> info) where THash : unmanaged, IHmacHashCore<THash>
	{
		ValidateExpandArguments<THash>(prk, output);
		ExpandCore<THash>(prk, output, info);
	}

	/// <summary>
	/// Derives key material using HKDF extract-and-expand.
	/// </summary>
	[SkipLocalsInit]
	public static void DeriveKey<THash>(ReadOnlySpan<byte> ikm, Span<byte> output, ReadOnlySpan<byte> salt, ReadOnlySpan<byte> info) where THash : unmanaged, IHmacHashCore<THash>
	{
		ValidateOutputLength<THash>(output);

		int hashLength = THash.HashLengthInBytes;
		using CryptoBuffer<byte> prk = new(stackalloc byte[hashLength]);
		HmacState<THash>.MacDestructive(salt, ikm, prk.Span);
		ExpandCore<THash>(prk.Span, output, info);
	}

	private static void ValidateExtractArguments<THash>(Span<byte> prk) where THash : unmanaged, IHmacHashCore<THash>
	{
		int hashLengthInBytes = THash.HashLengthInBytes;
		ArgumentOutOfRangeException.ThrowIfLessThan(prk.Length, hashLengthInBytes, nameof(prk));
	}

	private static void ValidateExpandArguments<THash>(ReadOnlySpan<byte> prk, Span<byte> output) where THash : unmanaged, IHmacHashCore<THash>
	{
		ValidateOutputLength<THash>(output);
		int hashLength = THash.HashLengthInBytes;
		ArgumentOutOfRangeException.ThrowIfLessThan(prk.Length, hashLength, nameof(prk));
	}

	private static void ValidateOutputLength<THash>(Span<byte> output) where THash : unmanaged, IHmacHashCore<THash>
	{
		ArgumentOutOfRangeException.ThrowIfZero(output.Length, nameof(output));

		int maxOkmLength = checked(255 * THash.HashLengthInBytes);
		ArgumentOutOfRangeException.ThrowIfGreaterThan(output.Length, maxOkmLength, nameof(output));
	}

	private static void ExpandCore<THash>(ReadOnlySpan<byte> prk, Span<byte> output, ReadOnlySpan<byte> info) where THash : unmanaged, IHmacHashCore<THash>
	{
		if (output.Length <= THash.HashLengthInBytes || !info.Overlaps(output, out int outputOffset))
		{
			ExpandBlocks<THash>(prk, output, info);
			return;
		}

		ExpandOverlapping<THash>(prk, output, info, outputOffset);
	}

	[SkipLocalsInit]
	private static void ExpandOverlapping<THash>(ReadOnlySpan<byte> prk, Span<byte> output, ReadOnlySpan<byte> info, int outputOffset) where THash : unmanaged, IHmacHashCore<THash>
	{
		int overlapOffset = Math.Max(0, outputOffset);
		int overlapEnd = (int)Math.Min(info.Length, (long)outputOffset + output.Length);
		int overlapLength = overlapEnd - overlapOffset;

		Debug.Assert(overlapLength > 0);
		using CryptoBuffer<byte> overlapBuffer = CryptoBuffer<byte>.ShouldUsePool(overlapLength) ? new CryptoBuffer<byte>(overlapLength) : new CryptoBuffer<byte>(stackalloc byte[overlapLength]);
		Span<byte> overlapCopy = overlapBuffer.Span;
		info.Slice(overlapOffset, overlapLength).CopyTo(overlapCopy);
		ExpandOverlappingBlocks<THash>(prk, output, info.Slice(0, overlapOffset), overlapCopy, info.Slice(overlapOffset + overlapLength));
	}

	[SkipLocalsInit]
	private static void ExpandBlocks<THash>(ReadOnlySpan<byte> prk, Span<byte> output, ReadOnlySpan<byte> info) where THash : unmanaged, IHmacHashCore<THash>
	{
		int hashLength = THash.HashLengthInBytes;
		byte counter = 0;
		ReadOnlySpan<byte> counterSpan = counter.AsReadOnlySpan();
		ReadOnlySpan<byte> previous = ReadOnlySpan<byte>.Empty;
		Span<byte> remainingOutput = output;
		Unsafe.SkipInit(out HmacState<THash> hmac);

		try
		{
			hmac.Initialize(prk);

			while (!remainingOutput.IsEmpty)
			{
				++counter;
				if (!previous.IsEmpty)
				{
					hmac.Append(previous);
				}

				hmac.Append(info);
				hmac.Append(counterSpan);

				if (remainingOutput.Length >= hashLength)
				{
					Span<byte> block = remainingOutput.Slice(0, hashLength);

					if (remainingOutput.Length == hashLength)
					{
						hmac.GetMacDestructive(block);
						break;
					}

					hmac.GetMacAndResetDestructive(block);
					previous = block;
					remainingOutput = remainingOutput.Slice(hashLength);
					continue;
				}

				// ReSharper disable once StackAllocInsideLoop
				using CryptoBuffer<byte> lastBlock = new(stackalloc byte[hashLength]);
				hmac.GetMacDestructive(lastBlock.Span);
				lastBlock.Span.Slice(0, remainingOutput.Length).CopyTo(remainingOutput);
				break;
			}
		}
		finally
		{
			hmac.ZeroMemory();
		}
	}

	// Keep segmented info out of the common loop so it has no per-block overlap branches.
	[SkipLocalsInit]
	private static void ExpandOverlappingBlocks<THash>(ReadOnlySpan<byte> prk, Span<byte> output, ReadOnlySpan<byte> infoPrefix, ReadOnlySpan<byte> overlapCopy, ReadOnlySpan<byte> infoSuffix) where THash : unmanaged, IHmacHashCore<THash>
	{
		int hashLength = THash.HashLengthInBytes;
		byte counter = 0;
		ReadOnlySpan<byte> counterSpan = counter.AsReadOnlySpan();
		ReadOnlySpan<byte> previous = ReadOnlySpan<byte>.Empty;
		Span<byte> remainingOutput = output;
		Unsafe.SkipInit(out HmacState<THash> hmac);

		try
		{
			hmac.Initialize(prk);

			while (!remainingOutput.IsEmpty)
			{
				++counter;
				if (!previous.IsEmpty)
				{
					hmac.Append(previous);
				}

				if (!infoPrefix.IsEmpty)
				{
					hmac.Append(infoPrefix);
				}

				hmac.Append(overlapCopy);

				if (!infoSuffix.IsEmpty)
				{
					hmac.Append(infoSuffix);
				}

				hmac.Append(counterSpan);

				if (remainingOutput.Length >= hashLength)
				{
					Span<byte> block = remainingOutput.Slice(0, hashLength);

					if (remainingOutput.Length == hashLength)
					{
						hmac.GetMacDestructive(block);
						break;
					}

					hmac.GetMacAndResetDestructive(block);
					previous = block;
					remainingOutput = remainingOutput.Slice(hashLength);
					continue;
				}

				// ReSharper disable once StackAllocInsideLoop
				using CryptoBuffer<byte> lastBlock = new(stackalloc byte[hashLength]);
				hmac.GetMacDestructive(lastBlock.Span);
				lastBlock.Span.Slice(0, remainingOutput.Length).CopyTo(remainingOutput);
				break;
			}
		}
		finally
		{
			hmac.ZeroMemory();
		}
	}
}
