using CryptoBase.Hashes.Sha3;
using System.Runtime.InteropServices;
using System.Runtime.Intrinsics;

namespace CryptoBase.Tests.Hashes.Sha3;

public abstract class KeccakP1600KernelCase : IKernelCase
{
	public static IEnumerable<KeccakP1600KernelCase> All()
	{
		yield return new Kernel<KeccakP1600Times1>();
		yield return new Kernel<KeccakP1600Times2>();
		yield return new Kernel<KeccakP1600Times4>();
		yield return new Kernel<KeccakP1600Times8>();
	}

	public static KeccakP1600KernelCase For(int lanes)
	{
		return All().Single(kernel => kernel.Lanes == lanes);
	}

	// The lanes between which KeccakP1600Times2.Permute picks by the CPU model, so that on any one runner the kernel leaves the other untested; these cases run each wherever it is supported.
	public static IEnumerable<KeccakP1600KernelCase> Variants()
	{
		yield return new Variant<KeccakP1600Times2>(KeccakP1600Times2.IsSupported);
		yield return new Variant<KeccakP1600Times2Sha3>(KeccakP1600Times2Sha3.IsSupported);
	}

	public abstract Type KernelType { get; }

	public abstract bool IsSupported { get; }

	public abstract int Lanes { get; }

	// Permutes the 25 * Lanes interleaved words at the start of state.
	public abstract void Permute(Span<ulong> state);

	public override string ToString()
	{
		return KernelType.Name;
	}

	private sealed class Variant<TLanes>(bool isSupported) : KeccakP1600KernelCase where TLanes : IKeccakP1600Lanes<Vector128<ulong>>
	{
		public override Type KernelType => typeof(TLanes);

		public override bool IsSupported => isSupported;

		public override int Lanes => KeccakP1600Times2.Lanes;

		public override void Permute(Span<ulong> state)
		{
			ArgumentOutOfRangeException.ThrowIfLessThan(state.Length, 25 * Lanes);

			KeccakP1600Interleaved.Permute<Vector128<ulong>, TLanes>(ref MemoryMarshal.GetReference(state));
		}

		public override string ToString()
		{
			return $"{KernelType.Name} lanes";
		}
	}

	private sealed class Kernel<TKernel> : KeccakP1600KernelCase where TKernel : IKeccakP1600Kernel
	{
		public override Type KernelType => typeof(TKernel);

		public override bool IsSupported => TKernel.IsSupported;

		public override int Lanes => TKernel.Lanes;

		public override void Permute(Span<ulong> state)
		{
			ArgumentOutOfRangeException.ThrowIfLessThan(state.Length, 25 * TKernel.Lanes);

			TKernel.Permute(ref MemoryMarshal.GetReference(state));
		}
	}
}
