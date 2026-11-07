using CryptoBase.Hashes.SM3;
using System.Runtime.InteropServices;
using System.Runtime.Intrinsics;

namespace CryptoBase.Tests.Hashes.SM3;

public abstract class SM3LanesCase : IKernelCase
{
	public static IEnumerable<SM3LanesCase> All()
	{
		yield return new Lanes<SM3Vector128, Vector128<uint>>();
		yield return new Lanes<SM3Vector256, Vector256<uint>>();
		yield return new Lanes<SM3Vector512, Vector512<uint>>();
	}

	public abstract Type KernelType { get; }

	public abstract bool IsSupported { get; }

	public abstract int LaneCount { get; }

	// Compresses block into state, lane by lane, both word-major: word j of lane i at j·LaneCount + i.
	public abstract void Compress(uint[] state, uint[] block);

	// Compress for two groups of lanes at once.
	public abstract void Compress(uint[] state0, uint[] block0, uint[] state1, uint[] block1);

	// The KDF blocks SM3(m ‖ ct) for ct from counter on, the last cut to fit destination, for the message m that prefix has absorbed.
	internal abstract void Write(in SM3Core prefix, uint counter, Span<byte> destination);

	public override string ToString()
	{
		return KernelType.Name;
	}

	private sealed class Lanes<TLanes, TVector> : SM3LanesCase where TLanes : ISM3Lanes<TVector> where TVector : unmanaged
	{
		public override Type KernelType => typeof(TLanes);

		public override bool IsSupported => TLanes.IsSupported;

		public override int LaneCount => TLanes.Lanes;

		public override void Compress(uint[] state, uint[] block)
		{
			TVector[] stateVectors = MemoryMarshal.Cast<uint, TVector>(state).ToArray();
			TVector[] schedule = new TVector[68];
			MemoryMarshal.Cast<uint, TVector>(block).CopyTo(schedule);
			SM3Lanes<TLanes, TVector>.Compress(ref stateVectors[0], ref schedule[0]);
			MemoryMarshal.Cast<TVector, uint>(stateVectors).CopyTo(state);
		}

		public override void Compress(uint[] state0, uint[] block0, uint[] state1, uint[] block1)
		{
			TVector[] stateVectors0 = MemoryMarshal.Cast<uint, TVector>(state0).ToArray();
			TVector[] stateVectors1 = MemoryMarshal.Cast<uint, TVector>(state1).ToArray();
			TVector[] schedule0 = new TVector[68];
			TVector[] schedule1 = new TVector[68];
			MemoryMarshal.Cast<uint, TVector>(block0).CopyTo(schedule0);
			MemoryMarshal.Cast<uint, TVector>(block1).CopyTo(schedule1);
			SM3Lanes<TLanes, TVector>.Compress(ref stateVectors0[0], ref schedule0[0], ref stateVectors1[0], ref schedule1[0]);
			MemoryMarshal.Cast<TVector, uint>(stateVectors0).CopyTo(state0);
			MemoryMarshal.Cast<TVector, uint>(stateVectors1).CopyTo(state1);
		}

		internal override void Write(in SM3Core prefix, uint counter, Span<byte> destination)
		{
			prefix.GetCounterBlocks(out SM3CounterBlocks blocks);
			SM3Lanes<TLanes, TVector>.Write(in blocks, counter, destination);
		}
	}
}
