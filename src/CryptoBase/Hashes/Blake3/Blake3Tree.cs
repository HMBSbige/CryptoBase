using static CryptoBase.Hashes.Blake3.Blake3Constants;

namespace CryptoBase.Hashes.Blake3;

// Hashes whole subtrees with the widest kernel, keeping a wide row of chaining values on the way up so that parents fill the lanes too.
internal static class Blake3Tree
{
	// Chosen once, so that every dispatch and every length derived from Degree follows the same kernel. The dispatches test this constant in if chains, which the JIT folds before inlining; a switch, folded after, left ReduceToChildren worse register-allocated.
	internal static readonly Blake3TreeKernel Kernel = ChooseKernel();

	// The number of chunks that the kernel hashes side by side; Blake3Vector512x2 counts as the Blake3Vector512 it runs twice, since the leaf length and chunk mode interval that derive from this measured slower sized to its 32 chunks.
	internal static int Degree => Kernel switch
	{
		Blake3TreeKernel.Vector512x2 or Blake3TreeKernel.Vector512 => Blake3Vector512.Degree,
		Blake3TreeKernel.Vector256 => Blake3Vector256.Degree,
		Blake3TreeKernel.Vector128x2 => Blake3Vector128x2.Degree,
		Blake3TreeKernel.Vector128 => Blake3Vector128.Degree,
		_ => Blake3Scalar.Degree
	};

	[SkipLocalsInit]
	internal static void HashData(ReadOnlySpan<byte> source, ref readonly InlineArray8<uint> key, uint flags, Span<byte> destination, int maxDegreeOfParallelism, ThreadPoolHelperBudget budget)
	{
		Blake3Output output;

		if (source.Length <= ChunkLength)
		{
			Blake3Output.FromChunk(source, in key, Blake3Flags.ChunkStart, 0, flags, out output);
		}
		else
		{
			Unsafe.SkipInit(out InlineArray64<byte> children);

			if (maxDegreeOfParallelism is 1 || !Blake3Parallel.TryCompressSubtreeToParentNode(source, in key, flags, children, maxDegreeOfParallelism, budget))
			{
				CompressSubtreeToParentNode(source, in key, 0, flags, children);
			}

			Blake3Output.FromParent(children, in key, flags, out output);

			if (Blake3Flags.IsSecret(flags))
			{
				children.ZeroMemory();
			}
		}

		// Writing long output in parallel may fail for lack of memory, and the output, secret in the keyed hash and key derivation modes, is erased all the same.
		try
		{
			output.RootBytes(0, destination, maxDegreeOfParallelism, budget);
		}
		finally
		{
			if (Blake3Flags.IsSecret(flags))
			{
				output.ZeroMemory();
			}
		}
	}

	internal static void CompressSubtreeToParentNode(ReadOnlySpan<byte> input, ref readonly InlineArray8<uint> key, ulong chunkCounter, uint flags, Span<byte> output)
	{
		if (Kernel is Blake3TreeKernel.Vector512x2)
		{
			CompressSubtreeToParentNode<Blake3Vector512x2>(input, in key, chunkCounter, flags, output);
		}
		else if (Kernel is Blake3TreeKernel.Vector512)
		{
			CompressSubtreeToParentNode<Blake3Vector512>(input, in key, chunkCounter, flags, output);
		}
		else if (Kernel is Blake3TreeKernel.Vector256)
		{
			CompressSubtreeToParentNode<Blake3Vector256>(input, in key, chunkCounter, flags, output);
		}
		else if (Kernel is Blake3TreeKernel.Vector128x2)
		{
			CompressSubtreeToParentNode<Blake3Vector128x2>(input, in key, chunkCounter, flags, output);
		}
		else if (Kernel is Blake3TreeKernel.Vector128)
		{
			CompressSubtreeToParentNode<Blake3Vector128>(input, in key, chunkCounter, flags, output);
		}
		else
		{
			CompressSubtreeToParentNode<Blake3Scalar>(input, in key, chunkCounter, flags, output);
		}
	}

	internal static void ReduceToChildren(Span<byte> chainingValues, int count, ref readonly InlineArray8<uint> key, uint flags, Span<byte> output)
	{
		// Blake3Vector512x2 leaves all parents to Blake3Vector512.
		if (Kernel is Blake3TreeKernel.Vector512x2 or Blake3TreeKernel.Vector512)
		{
			ReduceToChildren<Blake3Vector512>(chainingValues, count, in key, flags, output);
		}
		else if (Kernel is Blake3TreeKernel.Vector256)
		{
			ReduceToChildren<Blake3Vector256>(chainingValues, count, in key, flags, output);
		}
		else if (Kernel is Blake3TreeKernel.Vector128x2)
		{
			ReduceToChildren<Blake3Vector128x2>(chainingValues, count, in key, flags, output);
		}
		else if (Kernel is Blake3TreeKernel.Vector128)
		{
			ReduceToChildren<Blake3Vector128>(chainingValues, count, in key, flags, output);
		}
		else
		{
			ReduceToChildren<Blake3Scalar>(chainingValues, count, in key, flags, output);
		}
	}

	internal static void XofMany(ref readonly uint cv, ref byte block, uint blockLength, ulong counter, uint flags, nuint count, ref byte output)
	{
		// The paired kernels have no XOF of their own.
		if (Kernel is Blake3TreeKernel.Vector512x2 or Blake3TreeKernel.Vector512)
		{
			Blake3Vector512.XofMany(in cv, ref block, blockLength, counter, flags, count, ref output);
		}
		else if (Kernel is Blake3TreeKernel.Vector256)
		{
			Blake3Vector256.XofMany(in cv, ref block, blockLength, counter, flags, count, ref output);
		}
		else if (Kernel is Blake3TreeKernel.Vector128x2 or Blake3TreeKernel.Vector128)
		{
			Blake3Vector128.XofMany(in cv, ref block, blockLength, counter, flags, count, ref output);
		}
		else
		{
			Blake3Scalar.XofMany(in cv, ref block, blockLength, counter, flags, count, ref output);
		}
	}

	[SkipLocalsInit]
	internal static void CompressSubtreeToParentNode<TKernel>(ReadOnlySpan<byte> input, ref readonly InlineArray8<uint> key, ulong chunkCounter, uint flags, Span<byte> output) where TKernel : IBlake3Kernel
	{
		Debug.Assert(input.Length > ChunkLength);
		Debug.Assert(output.Length is 2 * OutLength);

		Span<byte> chainingValues = stackalloc byte[MaxWidth<TKernel>() * OutLength];
		int count = CompressSubtreeWide<TKernel>(input, in key, chunkCounter, flags, chainingValues);
		ReduceToChildren<TKernel>(chainingValues, count, in key, flags, output);
	}

	private static void ReduceToChildren<TKernel>(Span<byte> chainingValues, int count, ref readonly InlineArray8<uint> key, uint flags, Span<byte> output) where TKernel : IBlake3Kernel
	{
		Debug.Assert(count >= 2);

		while (count > 2)
		{
			count = CompressParents<TKernel>(chainingValues, count, in key, flags, chainingValues);
		}

		chainingValues.Slice(0, 2 * OutLength).CopyTo(output);
	}

	[SkipLocalsInit]
	private static int CompressSubtreeWide<TKernel>(ReadOnlySpan<byte> input, ref readonly InlineArray8<uint> key, ulong chunkCounter, uint flags, Span<byte> output) where TKernel : IBlake3Kernel
	{
		if (input.Length <= TKernel.Degree * ChunkLength)
		{
			return CompressChunks<TKernel>(input, in key, chunkCounter, flags, output);
		}

		int leftLength = (1 << BitOperations.Log2((uint)(input.Length - 1) / ChunkLength)) * ChunkLength;

		int leftWidth = TKernel.Degree is 1 && leftLength > ChunkLength ? 2 : TKernel.Degree;

		Span<byte> chainingValues = stackalloc byte[2 * MaxWidth<TKernel>() * OutLength];
		int leftCount = CompressSubtreeWide<TKernel>(input.Slice(0, leftLength), in key, chunkCounter, flags, chainingValues);
		Debug.Assert(leftCount == leftWidth);

		int rightCount = CompressSubtreeWide<TKernel>(input.Slice(leftLength), in key, chunkCounter + (ulong)(leftLength / ChunkLength), flags, chainingValues.Slice(leftWidth * OutLength));

		if (leftWidth is 1)
		{
			chainingValues.Slice(0, 2 * OutLength).CopyTo(output);
			return 2;
		}

		return CompressParents<TKernel>(chainingValues, leftWidth + rightCount, in key, flags, output);
	}

	private static int CompressChunks<TKernel>(ReadOnlySpan<byte> input, ref readonly InlineArray8<uint> key, ulong chunkCounter, uint flags, Span<byte> output) where TKernel : IBlake3Kernel
	{
		Debug.Assert(input.Length > 0 && input.Length <= TKernel.Degree * ChunkLength);

		TKernel.HashChunks(ref MemoryMarshal.GetReference(input), (uint)input.Length, in key[0], chunkCounter, flags, ref MemoryMarshal.GetReference(output));
		return (input.Length - 1) / ChunkLength + 1;
	}

	private static int CompressParents<TKernel>(ReadOnlySpan<byte> chainingValues, int count, ref readonly InlineArray8<uint> key, uint flags, Span<byte> output) where TKernel : IBlake3Kernel
	{
		Debug.Assert(count >= 2);

		int parents = count / 2;
		ref byte destination = ref MemoryMarshal.GetReference(output);
		TKernel.HashParents(ref MemoryMarshal.GetReference(chainingValues), (uint)parents, in key[0], flags, ref destination);

		if ((count & 1) is 0)
		{
			return parents;
		}

		chainingValues.Slice(2 * parents * OutLength, OutLength).CopyTo(output.Slice(parents * OutLength));
		return parents + 1;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static int MaxWidth<TKernel>() where TKernel : IBlake3Kernel
	{
		return Math.Max(TKernel.Degree, 2);
	}

	// The widest kernel supported, or its paired form where that measured faster.
	private static Blake3TreeKernel ChooseKernel()
	{
		if (Blake3Vector512x2.IsPreferred)
		{
			return Blake3TreeKernel.Vector512x2;
		}

		if (Blake3Vector512.IsSupported)
		{
			return Blake3TreeKernel.Vector512;
		}

		if (Blake3Vector256.IsSupported)
		{
			return Blake3TreeKernel.Vector256;
		}

		if (Blake3Vector128x2.IsPreferred)
		{
			return Blake3TreeKernel.Vector128x2;
		}

		return Blake3Vector128.IsSupported ? Blake3TreeKernel.Vector128 : Blake3TreeKernel.Scalar;
	}
}
