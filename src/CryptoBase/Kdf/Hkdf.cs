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
	public static int Extract<TCore>(ReadOnlySpan<byte> ikm, ReadOnlySpan<byte> salt, Span<byte> prk) where TCore : unmanaged, IHmacHashCore<TCore>
	{
		ArgumentOutOfRangeException.ThrowIfLessThan(prk.Length, TCore.HashLength, nameof(prk));

		return HmacAlgorithm<TCore>.Mac(salt, ikm, prk);
	}

	/// <summary>
	/// Expands a pseudorandom key using HKDF.
	/// </summary>
	public static void Expand<TCore>(ReadOnlySpan<byte> prk, Span<byte> output, ReadOnlySpan<byte> info) where TCore : unmanaged, IHmacHashCore<TCore>
	{
		ValidateExpandArguments<TCore>(prk, output);
		ExpandCore<TCore>(prk, output, info);
	}

	/// <summary>
	/// Derives key material using HKDF extract-and-expand.
	/// </summary>
	[SkipLocalsInit]
	public static void DeriveKey<TCore>(ReadOnlySpan<byte> ikm, Span<byte> output, ReadOnlySpan<byte> salt, ReadOnlySpan<byte> info) where TCore : unmanaged, IHmacHashCore<TCore>
	{
		ValidateOutputLength<TCore>(output);

		int hashLength = TCore.HashLength;
		using CryptoBuffer<byte> prk = new(stackalloc byte[hashLength]);
		HmacState<TCore>.Mac(salt, ikm, prk.Span);
		ExpandCore<TCore>(prk.Span, output, info);
	}

	private static void ValidateExpandArguments<TCore>(ReadOnlySpan<byte> prk, Span<byte> output) where TCore : unmanaged, IHmacHashCore<TCore>
	{
		ValidateOutputLength<TCore>(output);
		int hashLength = TCore.HashLength;
		ArgumentOutOfRangeException.ThrowIfLessThan(prk.Length, hashLength, nameof(prk));
	}

	private static void ValidateOutputLength<TCore>(Span<byte> output) where TCore : unmanaged, IHmacHashCore<TCore>
	{
		ArgumentOutOfRangeException.ThrowIfZero(output.Length, nameof(output));

		int maxOkmLength = checked(255 * TCore.HashLength);
		ArgumentOutOfRangeException.ThrowIfGreaterThan(output.Length, maxOkmLength, nameof(output));
	}

	private static void ExpandCore<TCore>(ReadOnlySpan<byte> prk, Span<byte> output, ReadOnlySpan<byte> info) where TCore : unmanaged, IHmacHashCore<TCore>
	{
		if (output.Length <= TCore.HashLength || !info.Overlaps(output, out int outputOffset))
		{
			ExpandBlocks<TCore>(prk, output, info);
			return;
		}

		ExpandOverlapping<TCore>(prk, output, info, outputOffset);
	}

	[SkipLocalsInit]
	private static void ExpandOverlapping<TCore>(ReadOnlySpan<byte> prk, Span<byte> output, ReadOnlySpan<byte> info, int outputOffset) where TCore : unmanaged, IHmacHashCore<TCore>
	{
		int overlapOffset = Math.Max(0, outputOffset);
		int overlapEnd = (int)Math.Min(info.Length, (long)outputOffset + output.Length);
		int overlapLength = overlapEnd - overlapOffset;

		Debug.Assert(overlapLength > 0);
		using CryptoBuffer<byte> overlapBuffer = CryptoBuffer<byte>.ShouldUsePool(overlapLength) ? new CryptoBuffer<byte>(overlapLength) : new CryptoBuffer<byte>(stackalloc byte[overlapLength]);
		Span<byte> overlapCopy = overlapBuffer.Span;
		info.Slice(overlapOffset, overlapLength).CopyTo(overlapCopy);
		ExpandOverlappingBlocks<TCore>(prk, output, info.Slice(0, overlapOffset), overlapCopy, info.Slice(overlapOffset + overlapLength));
	}

	[SkipLocalsInit]
	private static void ExpandBlocks<TCore>(ReadOnlySpan<byte> prk, Span<byte> output, ReadOnlySpan<byte> info) where TCore : unmanaged, IHmacHashCore<TCore>
	{
		int hashLength = TCore.HashLength;
		byte counter = 0;
		ReadOnlySpan<byte> counterSpan = counter.AsReadOnlySpan();
		ReadOnlySpan<byte> previous = ReadOnlySpan<byte>.Empty;
		Span<byte> remainingOutput = output;
		Unsafe.SkipInit(out HmacState<TCore> hmac);

		try
		{
			hmac.Initialize(prk, output.Length > hashLength);

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
	private static void ExpandOverlappingBlocks<TCore>(ReadOnlySpan<byte> prk, Span<byte> output, ReadOnlySpan<byte> infoPrefix, ReadOnlySpan<byte> overlapCopy, ReadOnlySpan<byte> infoSuffix) where TCore : unmanaged, IHmacHashCore<TCore>
	{
		int hashLength = TCore.HashLength;
		byte counter = 0;
		ReadOnlySpan<byte> counterSpan = counter.AsReadOnlySpan();
		ReadOnlySpan<byte> previous = ReadOnlySpan<byte>.Empty;
		Span<byte> remainingOutput = output;
		Unsafe.SkipInit(out HmacState<TCore> hmac);

		try
		{
			hmac.Initialize(prk, output.Length > hashLength);

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
