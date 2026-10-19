using CryptoBase.Hashes.Sha3;
using System.Runtime.InteropServices;

namespace CryptoBase.Tests.Hashes.Sha3;

public abstract class KeccakP1600KernelCase
{
	public static IEnumerable<KeccakP1600KernelCase> All()
	{
		yield return new Kernel<KeccakP1600Times1>();
		yield return new Kernel<KeccakP1600Times2>();
		yield return new Kernel<KeccakP1600Times4>();
		yield return new Kernel<KeccakP1600Times8>();
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
