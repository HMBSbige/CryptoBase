using CryptoBase.Ciphers.Blocks.Aes;

namespace CryptoBase.Ciphers.Modes.Gcm;

internal static partial class AesGcmX86
{
	[MethodImpl(MethodImplOptions.NoInlining)]
	internal static void Transform<TDirection>(in AesCipherX86 aes, Vector128<byte> counter, ReadOnlySpan<byte> source, Span<byte> destination, ref GHashKey hashKey, ref Vector128<byte> accumulator, ref Vector128<byte> tagMask, Vector128<byte> associatedDataBlock, Vector128<byte> lengthBlock) where TDirection : struct, IBlockDirection
	{
		tagMask = aes.Encrypt(tagMask);
		ref readonly GHashVector128PrecomputedKey powers = ref hashKey.GetVector128().Value;
		accumulator = accumulator.ReverseEndianness128();
		int processed = 0;

		if (source.Length >= 64)
		{
			// The block kernels take no AAD block, so hash it first.
			accumulator ^= HashBlock(associatedDataBlock, in powers);
			associatedDataBlock = Vector128<byte>.Zero;

			if (source.Length >= WideThreshold)
			{
				processed = Transform8<TDirection>(in aes, ref counter, source, destination, ref accumulator, in powers);
			}

			if (source.Length - processed >= 64)
			{
				processed += Transform4<TDirection>(in aes, ref counter, source.Slice(processed), destination.Slice(processed), ref accumulator, in powers);
			}
		}

		accumulator = TransformFinal<TDirection>(in aes, counter, ref Unsafe.Add(ref MemoryMarshal.GetReference(source), processed), ref Unsafe.Add(ref MemoryMarshal.GetReference(destination), processed), source.Length - processed, associatedDataBlock, lengthBlock, accumulator, in powers);
		accumulator = accumulator.ReverseEndianness128();
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector128<byte> TransformFinal<TDirection>(in AesCipherX86 aes, Vector128<byte> counter, ref byte input, ref byte output, int length, Vector128<byte> associatedDataBlock, Vector128<byte> lengthBlock, Vector128<byte> accumulator, in GHashVector128PrecomputedKey powers) where TDirection : struct, IBlockDirection
	{
		Debug.Assert(length is >= 0 and <= GcmFinalBlocks.MaxLength);

		if (length is 0)
		{
			return HashLengthBlock(accumulator, associatedDataBlock, lengthBlock, in powers);
		}

		EncryptCounters4(in aes, counter, out Vector128<byte> k0, out Vector128<byte> k1, out Vector128<byte> k2, out Vector128<byte> k3);

		if (TDirection.IsDecrypt)
		{
			// Load the ciphertext before writing plaintext, including when the buffers overlap.
			GcmFinalBlocks.Load(ref input, length, out Vector128<byte> c0, out Vector128<byte> c1, out Vector128<byte> c2, out Vector128<byte> c3);
			GcmFinalBlocks.Xor(ref k0, ref k1, ref k2, ref k3, ref input, ref output, length);
			return HashFinal(accumulator, associatedDataBlock, c0, c1, c2, c3, GcmFinalBlocks.GetBlockCount(length), lengthBlock, in powers);
		}

		GcmFinalBlocks.Xor(ref k0, ref k1, ref k2, ref k3, ref input, ref output, length);
		return HashFinal(accumulator, associatedDataBlock, k0, k1, k2, k3, GcmFinalBlocks.GetBlockCount(length), lengthBlock, in powers);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void EncryptCounters4(in AesCipherX86 aes, Vector128<byte> counter, out Vector128<byte> k0, out Vector128<byte> k1, out Vector128<byte> k2, out Vector128<byte> k3)
	{
		uint value = BinaryPrimitives.ReverseEndianness(counter.AsUInt32().GetElement(3));
		Vector128<byte> prefix = GetCounterPrefix(counter);
		k0 = counter;
		k1 = CreateCounter(prefix, value + 1u);
		k2 = CreateCounter(prefix, value + 2u);
		k3 = CreateCounter(prefix, value + 3u);
		aes.Encrypt4(ref k0, ref k1, ref k2, ref k3);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector128<byte> HashBlock(Vector128<byte> block, in GHashVector128PrecomputedKey powers)
	{
		MultiplyBlock(block, Vector128<byte>.Zero, in powers, 1, out Vector128<byte> lo, out Vector128<byte> hi);
		return GHashX86.ReducePrepared(lo, hi);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector128<byte> HashLengthBlock(Vector128<byte> accumulator, Vector128<byte> associatedDataBlock, Vector128<byte> lengthBlock, in GHashVector128PrecomputedKey powers)
	{
		MultiplyBlock(lengthBlock, accumulator, in powers, 1, out Vector128<byte> lo, out Vector128<byte> hi);
		AccumulateBlock(associatedDataBlock, in powers, 2, ref lo, ref hi);
		return GHashX86.ReducePrepared(lo, hi);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector128<byte> HashFinal(Vector128<byte> accumulator, Vector128<byte> associatedDataBlock, Vector128<byte> c0, Vector128<byte> c1, Vector128<byte> c2, Vector128<byte> c3, int blockCount, Vector128<byte> lengthBlock, in GHashVector128PrecomputedKey powers)
	{
		Vector128<byte> lo;
		Vector128<byte> hi;

		switch (blockCount)
		{
			case 1:
			{
				MultiplyBlock(c0, accumulator, in powers, 2, out lo, out hi);
				AccumulateBlock(associatedDataBlock, in powers, 3, ref lo, ref hi);
				break;
			}
			case 2:
			{
				MultiplyBlock(c0, accumulator, in powers, 3, out lo, out hi);
				AccumulateBlock(c1, in powers, 2, ref lo, ref hi);
				AccumulateBlock(associatedDataBlock, in powers, 4, ref lo, ref hi);
				break;
			}
			case 3:
			{
				MultiplyBlock(c0, accumulator, in powers, 4, out lo, out hi);
				AccumulateBlock(c1, in powers, 3, ref lo, ref hi);
				AccumulateBlock(c2, in powers, 2, ref lo, ref hi);
				AccumulateBlock(associatedDataBlock, in powers, 5, ref lo, ref hi);
				break;
			}
			default:
			{
				MultiplyBlock(c0, accumulator, in powers, 5, out lo, out hi);
				AccumulateBlock(c1, in powers, 4, ref lo, ref hi);
				AccumulateBlock(c2, in powers, 3, ref lo, ref hi);
				AccumulateBlock(c3, in powers, 2, ref lo, ref hi);
				AccumulateBlock(associatedDataBlock, in powers, 6, ref lo, ref hi);
				break;
			}
		}

		AccumulateBlock(lengthBlock, in powers, 1, ref lo, ref hi);
		return GHashX86.ReducePrepared(lo, hi);
	}
}
