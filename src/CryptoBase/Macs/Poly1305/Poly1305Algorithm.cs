using CryptoBase.Abstractions.Macs;

namespace CryptoBase.Macs.Poly1305;

/// <summary>
/// Provides the one-shot Poly1305 message authentication code algorithm.
/// </summary>
public readonly struct Poly1305Algorithm : IOneShotMacAlgorithm
{
	/// <summary>
	/// The Poly1305 key length, in bytes.
	/// </summary>
	public const int KeyLengthInBytes = 32;

	internal const int BlockSizeInBytes = 16;

	private const int Sse2BlockSizeInBytes = 2 * BlockSizeInBytes;
	private const int Avx2BlockSizeInBytes = 4 * BlockSizeInBytes;
	private const int Avx512BlockSizeInBytes = 8 * BlockSizeInBytes;
	private const int Sse2MinimumParallelLength = 2 * Sse2BlockSizeInBytes;
	private const int X86Sse2MinimumInputLength = 3 * BlockSizeInBytes;
	private const int X64Sse2ContiguousMinimumParallelLength = 7 * Sse2BlockSizeInBytes;
	private const int X64Sse2TotalMinimumParallelLength = 8 * Sse2BlockSizeInBytes;
	private const int X86Avx2MinimumParallelLength = 2 * Avx2BlockSizeInBytes;
	private const int X64Avx2MinimumParallelLength = 3 * Avx2BlockSizeInBytes;
	private const int X64Avx2TailAmortizationLength = 8 * Avx2BlockSizeInBytes;
	private const int X86Avx2TailAmortizationLength = 9 * Avx2BlockSizeInBytes;
	private const int Avx512MinimumParallelLength = 4 * Avx512BlockSizeInBytes;
	private const int AdvSimdMinimumParallelLength = 4 * Avx2BlockSizeInBytes;

	/// <inheritdoc />
	public static int MacLength => 16;

	/// <inheritdoc />
	public static int Mac(ReadOnlySpan<byte> key, ReadOnlySpan<byte> source, Span<byte> destination)
	{
		ArgumentOutOfRangeException.ThrowIfLessThan(destination.Length, MacLength, nameof(destination));
		ArgumentOutOfRangeException.ThrowIfNotEqual(key.Length, KeyLengthInBytes, nameof(key));

		return MacSelected(key, source, destination);
	}

	internal static void MacPaddedSegments(ReadOnlySpan<byte> key, ReadOnlySpan<byte> firstSegment, ReadOnlySpan<byte> secondSegment, ReadOnlySpan<byte> thirdSegment, Span<byte> destination)
	{
		Debug.Assert(key.Length is KeyLengthInBytes);
		Debug.Assert(destination.Length >= MacLength);

		MacPaddedSegmentsSelected(key, firstSegment, secondSegment, thirdSegment, destination);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static int MacSelected(ReadOnlySpan<byte> key, ReadOnlySpan<byte> source, Span<byte> destination)
	{
		if (ShouldUseAvx512(source.Length))
		{
			return MacCore<Poly1305Avx512>(key, source, destination);
		}

		if (ShouldUseAvx2(source.Length))
		{
			return MacCore<Poly1305Avx2>(key, source, destination);
		}

		if (ShouldUseSse2(source.Length))
		{
			return MacCore<Poly1305Sse2>(key, source, destination);
		}

		if (ShouldUseAdvSimd(source.Length))
		{
			return MacCore<Poly1305AdvSimd>(key, source, destination);
		}

		return MacCore<Poly1305Software>(key, source, destination);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void MacPaddedSegmentsSelected(ReadOnlySpan<byte> key, ReadOnlySpan<byte> firstSegment, ReadOnlySpan<byte> secondSegment, ReadOnlySpan<byte> thirdSegment, Span<byte> destination)
	{
		if (ShouldUseAvx512(firstSegment.Length, secondSegment.Length, thirdSegment.Length))
		{
			MacPaddedSegmentsCore<Poly1305Avx512>(key, firstSegment, secondSegment, thirdSegment, destination);
			return;
		}

		if (ShouldUseAvx2(firstSegment.Length, secondSegment.Length, thirdSegment.Length))
		{
			MacPaddedSegmentsCore<Poly1305Avx2>(key, firstSegment, secondSegment, thirdSegment, destination);
			return;
		}

		if (ShouldUseSse2(firstSegment.Length, secondSegment.Length, thirdSegment.Length))
		{
			MacPaddedSegmentsCore<Poly1305Sse2>(key, firstSegment, secondSegment, thirdSegment, destination);
			return;
		}

		if (ShouldUseAdvSimd(firstSegment.Length, secondSegment.Length, thirdSegment.Length))
		{
			MacPaddedSegmentsCore<Poly1305AdvSimd>(key, firstSegment, secondSegment, thirdSegment, destination);
			return;
		}

		MacPaddedSegmentsCore<Poly1305Software>(key, firstSegment, secondSegment, thirdSegment, destination);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static bool ShouldUseAvx512(int length)
	{
		return ShouldUseAvx512Core(length);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static bool ShouldUseAvx2(int length)
	{
		return ShouldUseAvx2Core(length & -Avx2BlockSizeInBytes, length & -Sse2BlockSizeInBytes);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static bool ShouldUseSse2(int length)
	{
		int parallelLength = length & -Sse2BlockSizeInBytes;
		return ShouldUseSse2Core(length, parallelLength, parallelLength);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static bool ShouldUseAdvSimd(int length)
	{
		return ShouldUseAdvSimdCore(length);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static bool ShouldUseAvx512(int firstLength, int secondLength, int thirdLength)
	{
		return ShouldUseAvx512Core(GetParallelLength(firstLength, secondLength, thirdLength, Avx512BlockSizeInBytes));
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static bool ShouldUseAvx2(int firstLength, int secondLength, int thirdLength)
	{
		long parallelLength = GetParallelLength(firstLength, secondLength, thirdLength, Avx2BlockSizeInBytes);
		long sse2ParallelLength = GetParallelLength(firstLength, secondLength, thirdLength, Sse2BlockSizeInBytes);
		return ShouldUseAvx2Core(parallelLength, sse2ParallelLength);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static bool ShouldUseSse2(int firstLength, int secondLength, int thirdLength)
	{
		long inputLength = firstLength + (long)secondLength + thirdLength;
		long parallelLength = GetParallelLength(firstLength, secondLength, thirdLength, Sse2BlockSizeInBytes);
		int maximumParallelLength = Math.Max(firstLength & -Sse2BlockSizeInBytes, Math.Max(secondLength & -Sse2BlockSizeInBytes, thirdLength & -Sse2BlockSizeInBytes));
		return ShouldUseSse2Core(inputLength, parallelLength, maximumParallelLength);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static bool ShouldUseAdvSimd(int firstLength, int secondLength, int thirdLength)
	{
		return ShouldUseAdvSimdCore(GetParallelLength(firstLength, secondLength, thirdLength, Avx2BlockSizeInBytes));
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static bool ShouldUseAvx512Core(long eligibleLength)
	{
		return Poly1305Avx512.IsSupported && eligibleLength >= Avx512MinimumParallelLength;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static bool ShouldUseAvx2Core(long parallelLength, long sse2ParallelLength)
	{
		if (!Poly1305Avx2.IsSupported)
		{
			return false;
		}

		int minimumParallelLength = X86Base.X64.IsSupported ? X64Avx2MinimumParallelLength : X86Avx2MinimumParallelLength;

		if (parallelLength < minimumParallelLength)
		{
			return false;
		}

		int tailAmortizationLength = X86Base.X64.IsSupported ? X64Avx2TailAmortizationLength : X86Avx2TailAmortizationLength;
		return parallelLength == sse2ParallelLength || parallelLength >= tailAmortizationLength;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static bool ShouldUseSse2Core(long inputLength, long parallelLength, long maximumParallelLength)
	{
		if (!Poly1305Sse2.IsSupported)
		{
			return false;
		}

		if (!X86Base.X64.IsSupported)
		{
			return parallelLength >= Sse2MinimumParallelLength || parallelLength >= Sse2BlockSizeInBytes && inputLength >= X86Sse2MinimumInputLength;
		}

		if (!Poly1305Avx2.IsSupported)
		{
			return parallelLength >= Sse2MinimumParallelLength;
		}

		return maximumParallelLength >= X64Sse2ContiguousMinimumParallelLength || parallelLength >= X64Sse2TotalMinimumParallelLength;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static bool ShouldUseAdvSimdCore(long eligibleLength)
	{
		return Poly1305AdvSimd.IsSupported && eligibleLength >= AdvSimdMinimumParallelLength;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static long GetParallelLength(int firstLength, int secondLength, int thirdLength, int blockSize)
	{
		return (firstLength & -blockSize) + (long)(secondLength & -blockSize) + (thirdLength & -blockSize);
	}

	[SkipLocalsInit]
	[MethodImpl(MethodImplOptions.NoInlining)]
	private static int MacCore<TState>(ReadOnlySpan<byte> key, ReadOnlySpan<byte> source, Span<byte> destination) where TState : unmanaged, IPoly1305State<TState>, allows ref struct
	{
		Unsafe.SkipInit(out TState state);
		TState.Initialize(ref state, key);

		try
		{
			state.AppendMessage(source);
			state.WriteMac(destination);
			return MacLength;
		}
		finally
		{
			state.ZeroMemory();
		}
	}

	[SkipLocalsInit]
	[MethodImpl(MethodImplOptions.NoInlining)]
	private static void MacPaddedSegmentsCore<TState>(ReadOnlySpan<byte> key, ReadOnlySpan<byte> firstSegment, ReadOnlySpan<byte> secondSegment, ReadOnlySpan<byte> thirdSegment, Span<byte> destination) where TState : unmanaged, IPoly1305State<TState>, allows ref struct
	{
		Unsafe.SkipInit(out TState state);
		TState.Initialize(ref state, key);

		try
		{
			state.AppendPaddedSegment(firstSegment);
			state.AppendPaddedSegment(secondSegment);
			state.AppendPaddedSegment(thirdSegment);
			state.WriteMac(destination);
		}
		finally
		{
			state.ZeroMemory();
		}
	}
}
