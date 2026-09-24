using System.Diagnostics.CodeAnalysis;

namespace CryptoBase.Ciphers.Modes.Gcm;

internal ref struct GHash : IDisposable
{
	internal const int BlockSizeInBytes = 16;
	private const int Vector128ShortThreshold = 16 * BlockSizeInBytes;
	private const int ArmShortThreshold = 8 * BlockSizeInBytes;

	private readonly ref GHashKey _key;
	private Vector128<byte> _accumulator;

	[UnscopedRef]
	internal ref Vector128<byte> Accumulator => ref _accumulator;

	private GHash(ref GHashKey key)
	{
		_key = ref key;
		_accumulator = default;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static long GetPaddedLength(int length)
	{
		return (long)length + BlockSizeInBytes - 1 & -BlockSizeInBytes;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static GHash Create(ref GHashKey key)
	{
		return new GHash(ref key);
	}

	public void Dispose()
	{
		_accumulator.ZeroMemory();
	}

	// Appends one independently padded segment to the keyed state.
	[MethodImpl(MethodImplOptions.NoInlining)]
	internal void AppendPaddedSegment(scoped ReadOnlySpan<byte> source)
	{
		AppendPaddedSegments(ref _accumulator, ref _key, source, default, default);
	}

	[MethodImpl(MethodImplOptions.NoInlining)]
	internal void AppendPaddedSegmentsShort(scoped ReadOnlySpan<byte> first, scoped ReadOnlySpan<byte> second = default)
	{
		if (first.IsEmpty && second.IsEmpty)
		{
			return;
		}

		if (GHashX86.IsSupported && GetPaddedLength(first.Length) + GetPaddedLength(second.Length) <= Vector128ShortThreshold)
		{
			GHashX86.AppendPaddedSegments(ref _accumulator, ref _key.GetVector128().Value, first, second, default);
		}
		else if (GHashArm.IsSupported && GetPaddedLength(first.Length) + GetPaddedLength(second.Length) <= ArmShortThreshold)
		{
			_key.GetArm().Value.AppendPaddedSegments(ref _accumulator, first, second);
		}
		else
		{
			AppendPaddedSegments(ref _accumulator, ref _key, first, second, default);
		}
	}

	internal Vector128<byte> Finish(scoped ReadOnlySpan<byte> first, scoped ReadOnlySpan<byte> second, scoped ReadOnlySpan<byte> third)
	{
		AppendPaddedSegments(ref _accumulator, ref _key, first, second, third);
		return _accumulator;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void AppendPaddedSegments(ref Vector128<byte> accumulator, ref GHashKey key, ReadOnlySpan<byte> first, ReadOnlySpan<byte> second, ReadOnlySpan<byte> third)
	{
		if (GHashX86.IsSupported)
		{
			GHashX86.AppendPaddedSegments(ref accumulator, ref key, first, second, third);
		}
		else if (GHashArm.IsSupported)
		{
			GHashArm.AppendPaddedSegments(ref accumulator, ref key, first, second, third);
		}
		else
		{
			GHashSoftware.AppendPaddedSegments(ref accumulator, in key.Value, first, second, third);
		}
	}
}
