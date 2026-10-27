using CryptoBase.Hashes.Blake3;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace CryptoBase.Tests.Hashes.Blake3;

public abstract class Blake3KernelCase : IKernelCase
{
	public static IEnumerable<Blake3KernelCase> All()
	{
		yield return new XofKernel<Blake3Scalar>();
		yield return new XofKernel<Blake3Vector128>();
		yield return new Kernel<Blake3Vector128x2>();
		yield return new XofKernel<Blake3Vector256>();
		yield return new Kernel<Blake3Vector256Rows>();
		yield return new XofKernel<Blake3Vector512>();
		yield return new Kernel<Blake3Vector512x2>();
		yield return new Kernel<Blake3Vector512Rows>();
	}

	public static IEnumerable<Blake3KernelCase> WithXof()
	{
		return All().Where(static kernel => kernel.KernelType.IsAssignableTo(typeof(IBlake3XofKernel)));
	}

	public abstract Type KernelType { get; }

	public abstract bool IsSupported { get; }

	public abstract int Degree { get; }

	public abstract void HashChunks(ReadOnlySpan<byte> input, uint[] key, ulong counter, uint flags, Span<byte> output);

	public abstract void HashParents(ReadOnlySpan<byte> input, int count, uint[] key, uint flags, Span<byte> output);

	public virtual void XofMany(uint[] chainingValue, ReadOnlySpan<byte> block, uint blockLength, ulong counter, uint flags, int count, Span<byte> output)
	{
		throw new NotSupportedException($"{this} is not listed as an {nameof(IBlake3XofKernel)}.");
	}

	public abstract void CompressSubtreeToParentNode(ReadOnlySpan<byte> input, uint[] key, ulong chunkCounter, uint flags, Span<byte> output);

	public override string ToString()
	{
		return KernelType.Name;
	}

	private class Kernel<TKernel> : Blake3KernelCase where TKernel : IBlake3Kernel
	{
		public override Type KernelType => typeof(TKernel);

		public override bool IsSupported => TKernel.IsSupported;

		public override int Degree => TKernel.Degree;

		public override void HashChunks(ReadOnlySpan<byte> input, uint[] key, ulong counter, uint flags, Span<byte> output)
		{
			ArgumentOutOfRangeException.ThrowIfZero(input.Length);
			ArgumentOutOfRangeException.ThrowIfLessThan(output.Length, ((input.Length - 1) / Blake3Reference.ChunkLength + 1) * Blake3Reference.OutLength);

			TKernel.HashChunks(ref MemoryMarshal.GetReference(input), (uint)input.Length, in key[0], counter, flags, ref MemoryMarshal.GetReference(output));
		}

		public override void HashParents(ReadOnlySpan<byte> input, int count, uint[] key, uint flags, Span<byte> output)
		{
			ArgumentOutOfRangeException.ThrowIfLessThan(input.Length, count * Blake3Reference.BlockLength);
			ArgumentOutOfRangeException.ThrowIfLessThan(output.Length, count * Blake3Reference.OutLength);

			TKernel.HashParents(ref MemoryMarshal.GetReference(input), (uint)count, in key[0], flags, ref MemoryMarshal.GetReference(output));
		}

		public override void CompressSubtreeToParentNode(ReadOnlySpan<byte> input, uint[] key, ulong chunkCounter, uint flags, Span<byte> output)
		{
			InlineArray8<uint> keyWords = default;
			key.CopyTo(keyWords);
			Blake3Tree.CompressSubtreeToParentNode<TKernel>(input, in keyWords, chunkCounter, flags, output);
		}
	}

	private sealed class XofKernel<TKernel> : Kernel<TKernel> where TKernel : IBlake3XofKernel
	{
		public override void XofMany(uint[] chainingValue, ReadOnlySpan<byte> block, uint blockLength, ulong counter, uint flags, int count, Span<byte> output)
		{
			ArgumentOutOfRangeException.ThrowIfNotEqual(block.Length, Blake3Reference.BlockLength);
			ArgumentOutOfRangeException.ThrowIfLessThan(output.Length, count * Blake3Reference.BlockLength);

			TKernel.XofMany(in chainingValue[0], ref MemoryMarshal.GetReference(block), blockLength, counter, flags, (uint)count, ref MemoryMarshal.GetReference(output));
		}
	}
}
