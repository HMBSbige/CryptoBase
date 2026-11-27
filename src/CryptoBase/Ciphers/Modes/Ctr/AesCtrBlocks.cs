using CryptoBase.Ciphers.Blocks.Aes;

namespace CryptoBase.Ciphers.Modes.Ctr;

// Encrypts the last counter of a short input together with the others, even when only part of its keystream is needed.
internal static class AesCtrBlocks<TCore, TIncrementer> where TCore : struct, IAesVectorCore where TIncrementer : struct, ICtrIncrementer
{
	private const int BlockSize = 16;

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static void XorShort(ref TCore core, ref CtrStreamState state, ReadOnlySpan<byte> source, Span<byte> destination)
	{
		Debug.Assert(source.Length is > BlockSize and <= 4 * BlockSize && destination.Length >= source.Length);
		Debug.Assert(state.Index is 0);

		if (source.Length <= 2 * BlockSize)
		{
			XorTwo(ref core, ref state, source, destination);
		}
		else if (source.Length <= 3 * BlockSize)
		{
			XorThree(ref core, ref state, source, destination);
		}
		else
		{
			XorFour(ref core, ref state, source, destination);
		}
	}

	// One reference to the whole stream state keeps every argument in a register on both x64 ABIs.
	[MethodImpl(MethodImplOptions.NoInlining)]
	private static void XorTwo(ref TCore core, ref CtrStreamState state, ReadOnlySpan<byte> source, Span<byte> destination)
	{
		Vector128<byte> first = state.Counter;
		Vector128<byte> current = TIncrementer.Inc(first.ReverseEndianness128());
		Vector128<byte> last = CtrLanes<TIncrementer>.Next(ref current);
		core.Encrypt2(ref first, ref last);
		state.Counter = current.ReverseEndianness128();
		BlockXor.XorStore1(ref MemoryMarshal.GetReference(source), ref MemoryMarshal.GetReference(destination), 0, ref first);
		XorLast(last, ref state, source, destination, BlockSize);
	}

	// Separate entry points let the JIT eliminate the unused fourth AES lane for three counters.
	[MethodImpl(MethodImplOptions.NoInlining)]
	private static void XorThree(ref TCore core, ref CtrStreamState state, ReadOnlySpan<byte> source, Span<byte> destination)
	{
		XorFourLanes(ref core, ref state, source, destination, false);
	}

	[MethodImpl(MethodImplOptions.NoInlining)]
	private static void XorFour(ref TCore core, ref CtrStreamState state, ReadOnlySpan<byte> source, Span<byte> destination)
	{
		XorFourLanes(ref core, ref state, source, destination, true);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void XorFourLanes(ref TCore core, ref CtrStreamState state, ReadOnlySpan<byte> source, Span<byte> destination, bool useFourth)
	{
		AesCtrPolicy<TIncrementer> policy = default;
		policy.Initialize(state.Counter, 4 * BlockSize);
		ref byte src = ref MemoryMarshal.GetReference(source);
		ref byte dst = ref MemoryMarshal.GetReference(destination);
		policy.Prepare4(ref src, 0, out Vector128<byte> v0, out Vector128<byte> v1, out Vector128<byte> v2, out Vector128<byte> v3);

		if (useFourth)
		{
			policy.SaveState(ref state.Counter);
		}
		else
		{
			state.Counter = v3;
		}

		core.Encrypt4(ref v0, ref v1, ref v2, ref v3);
		BlockXor.XorStore2(ref src, ref dst, 0, ref v0, ref v1);

		if (useFourth)
		{
			BlockXor.XorStore1(ref src, ref dst, 2 * BlockSize, ref v2);
			XorLast(v3, ref state, source, destination, 3 * BlockSize);
		}
		else
		{
			XorLast(v2, ref state, source, destination, 2 * BlockSize);
		}
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void XorLast(Vector128<byte> last, ref CtrStreamState state, ReadOnlySpan<byte> source, Span<byte> destination, int offset)
	{
		int length = source.Length - offset;

		if (length == BlockSize)
		{
			BlockXor.XorStore1(ref MemoryMarshal.GetReference(source), ref MemoryMarshal.GetReference(destination), (nuint)offset, ref last);
			return;
		}

		state.KeyStream = last;
		state.Index = length;
		FastUtils.XorLess16(state.KeyStream.AsSpan(), source.Slice(offset), destination.Slice(offset), length);
	}
}
