using System.Numerics;

namespace CryptoBase.Ciphers.Blocks.SM4;

internal static class SM4BlockDriver<TKernel> where TKernel : struct, ISM4Kernel
{
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static void ProcessBlocks(ref uint rk, ReadOnlySpan<byte> source, Span<byte> destination, bool singleBlock)
	{
		Debug.Assert(TKernel.MaxBlocks is 4 or 8 or 16 or 32 or 64);
		Debug.Assert(TKernel.IsSupported && source.Length % 16 is 0 && destination.Length >= source.Length);
		Debug.Assert(!singleBlock || source.Length is 16);

		if (singleBlock)
		{
			ProcessSingleBlock(ref rk, ref source.GetReference(), ref destination.GetReference());
			return;
		}

		if (source.IsEmpty)
		{
			return;
		}

		if (source.Length < 64)
		{
			Process4(source.Length / 16, ref rk, ref source.GetReference(), ref destination.GetReference());
			return;
		}

		ProcessFullBlocks(ref rk, ref source.GetReference(), ref destination.GetReference(), source.Length);
	}

	// Avoid duplicating the round loop at each public single-block call site.
	[MethodImpl(MethodImplOptions.NoInlining)]
	private static void ProcessSingleBlock(ref uint rk, ref byte source, ref byte destination)
	{
		TKernel.Process(4, 1, ref rk, ref source, ref destination);
	}

	[MethodImpl(MethodImplOptions.NoInlining)]
	private static void Process4(int count, ref uint rk, ref byte source, ref byte destination)
	{
		TKernel.Process(4, count, ref rk, ref source, ref destination);
	}

	[MethodImpl(MethodImplOptions.NoInlining)]
	private static void Process8(int count, ref uint rk, ref byte source, ref byte destination)
	{
		TKernel.Process(8, count, ref rk, ref source, ref destination);
	}

	[MethodImpl(MethodImplOptions.NoInlining)]
	private static void Process16(int count, ref uint rk, ref byte source, ref byte destination)
	{
		TKernel.Process(16, count, ref rk, ref source, ref destination);
	}

	[MethodImpl(MethodImplOptions.NoInlining)]
	private static void Process32(int count, ref uint rk, ref byte source, ref byte destination)
	{
		TKernel.Process(32, count, ref rk, ref source, ref destination);
	}

	[MethodImpl(MethodImplOptions.NoInlining)]
	private static void Process64(int count, ref uint rk, ref byte source, ref byte destination)
	{
		TKernel.Process(64, count, ref rk, ref source, ref destination);
	}

	[MethodImpl(MethodImplOptions.NoInlining)]
	private static void ProcessFullBlocks(ref uint rk, ref byte source, ref byte destination, int length)
	{
		int batchLength = TKernel.MaxBlocks * 16;
		int offset = 0;

		while (length - offset >= batchLength)
		{
			TKernel.Process(TKernel.MaxBlocks, TKernel.MaxBlocks, ref rk, ref Unsafe.Add(ref source, offset), ref Unsafe.Add(ref destination, offset));
			offset += batchLength;
		}

		if (offset < length)
		{
			ProcessRemainder((length - offset) / 16, ref rk, ref Unsafe.Add(ref source, offset), ref Unsafe.Add(ref destination, offset));
		}
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void ProcessRemainder(int count, ref uint rk, ref byte source, ref byte destination)
	{
		Debug.Assert(count > 0 && count < TKernel.MaxBlocks);

		if (count <= 4)
		{
			Process4(count, ref rk, ref source, ref destination);
		}
		else if (TKernel.MaxBlocks <= 8 || count <= 8)
		{
			Process8(count, ref rk, ref source, ref destination);
		}
		else if (TKernel.MaxBlocks <= 16 || count <= 16)
		{
			Process16(count, ref rk, ref source, ref destination);
		}
		else if (TKernel.MaxBlocks <= 32 || count <= 32)
		{
			Process32(count, ref rk, ref source, ref destination);
		}
		else
		{
			Process64(count, ref rk, ref source, ref destination);
		}
	}

	[SkipLocalsInit]
	[MethodImpl(MethodImplOptions.NoInlining)]
	internal static void ProcessPadded(int width, int count, ref uint rk, ref byte source, ref byte destination)
	{
		Debug.Assert(width >= 4 && width <= TKernel.MaxBlocks && BitOperations.IsPow2(width));
		Debug.Assert(count > 0 && count < width);
		using CryptoBuffer<byte> buffer = new(stackalloc byte[width * 16]);
		MemoryMarshal.CreateReadOnlySpan(ref source, count * 16).CopyTo(buffer.Span);
		ref byte scratch = ref buffer.Span.GetReference();
		TKernel.Process(width, width, ref rk, ref scratch, ref scratch);
		buffer.Span.Slice(0, count * 16).CopyTo(MemoryMarshal.CreateSpan(ref destination, count * 16));
	}
}
