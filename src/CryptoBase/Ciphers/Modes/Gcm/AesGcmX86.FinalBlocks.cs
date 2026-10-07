using CryptoBase.Ciphers.Blocks.Aes;

namespace CryptoBase.Ciphers.Modes.Gcm;

internal static partial class AesGcmX86
{
	[MethodImpl(MethodImplOptions.NoInlining)]
	internal static void Encrypt(in AesCipherX86 aes, Vector128<byte> counter, ReadOnlySpan<byte> source, Span<byte> destination, ref GHashKey hashKey, ref Vector128<byte> accumulator, ref Vector128<byte> tagMask, Vector128<byte> associatedDataBlock, Vector128<byte> lengthBlock)
	{
		tagMask = aes.Encrypt(tagMask);
		ref readonly GHashVector128PrecomputedKey powers = ref hashKey.GetVector128().Value;
		accumulator = accumulator.ReverseEndianness128();
		int processed = source.Length >= WideThreshold
			? Encrypt8(in aes, ref counter, source, destination, ref accumulator, in powers)
			: 0;

		if (source.Length - processed >= 64)
		{
			processed += Encrypt4(in aes, ref counter, source.Slice(processed), destination.Slice(processed), ref accumulator, in powers);
		}

		accumulator = EncryptFinal(in aes, counter, ref Unsafe.Add(ref source.GetReference(), processed), ref Unsafe.Add(ref destination.GetReference(), processed), source.Length - processed, associatedDataBlock, lengthBlock, accumulator, in powers);
		accumulator = accumulator.ReverseEndianness128();
	}

	[MethodImpl(MethodImplOptions.NoInlining)]
	internal static bool Decrypt(in AesCipherX86 aes, Vector128<byte> counter, Vector128<byte> j0, ref byte input, ref byte output, int length, ref byte tag, ref GHashKey hashKey, Vector128<byte> accumulator, Vector128<byte> associatedDataBlock, Vector128<byte> lengthBlock)
	{
		Debug.Assert(length is >= 0 and <= AesGcmFusion.MaxFusedDecryptionLength);
		Vector128<byte> tagMask = aes.Encrypt(j0);
		ref readonly GHashVector128PrecomputedKey powers = ref hashKey.GetVector128().Value;
		Vector128<byte> hash = accumulator.ReverseEndianness128();
		int bulkLength = length & -64;
		int finalLength = length - bulkLength;
		ref byte finalInput = ref Unsafe.Add(ref input, bulkLength);
		ref byte finalOutput = ref Unsafe.Add(ref output, bulkLength);

		for (int offset = 0; offset < bulkLength; offset += 64)
		{
			hash = HashBlocks4(hash, associatedDataBlock, ref Unsafe.Add(ref input, offset), in powers);
			associatedDataBlock = Vector128<byte>.Zero;
		}

		if (finalLength is 0)
		{
			hash = HashLengthBlock(hash, associatedDataBlock, lengthBlock, in powers);

			if (!FixedTime.Equals16(hash.ReverseEndianness128() ^ tagMask, Vector128.LoadUnsafe(ref tag)))
			{
				MemoryMarshal.CreateSpan(ref output, length).ZeroMemory();
				return false;
			}

			DecryptBlocks4(in aes, counter, ref input, ref output, bulkLength);
			return true;
		}

		EncryptCounters4(in aes, counter, (uint)bulkLength / 16, out Vector128<byte> k0, out Vector128<byte> k1, out Vector128<byte> k2, out Vector128<byte> k3);
		GcmFinalBlocks.Load(ref finalInput, finalLength, out Vector128<byte> c0, out Vector128<byte> c1, out Vector128<byte> c2, out Vector128<byte> c3);
		hash = HashFinal(hash, associatedDataBlock, c0, c1, c2, c3, GcmFinalBlocks.GetBlockCount(finalLength), lengthBlock, in powers);

		if (!FixedTime.Equals16(hash.ReverseEndianness128() ^ tagMask, Vector128.LoadUnsafe(ref tag)))
		{
			MemoryMarshal.CreateSpan(ref output, length).ZeroMemory();
			return false;
		}

		DecryptBlocks4(in aes, counter, ref input, ref output, bulkLength);
		GcmFinalBlocks.Xor(ref k0, ref k1, ref k2, ref k3, ref finalInput, ref finalOutput, finalLength);
		return true;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void DecryptBlocks4(in AesCipherX86 aes, Vector128<byte> counter, ref byte input, ref byte output, int length)
	{
		for (int offset = 0; offset < length; offset += 64)
		{
			EncryptCounters4(in aes, counter, (uint)offset / 16, out Vector128<byte> k0, out Vector128<byte> k1, out Vector128<byte> k2, out Vector128<byte> k3);
			BlockXor.XorStore4(ref input, ref output, (nuint)offset, ref k0, ref k1, ref k2, ref k3);
		}
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector128<byte> EncryptFinal(in AesCipherX86 aes, Vector128<byte> counter, ref byte input, ref byte output, int length, Vector128<byte> associatedDataBlock, Vector128<byte> lengthBlock, Vector128<byte> accumulator, in GHashVector128PrecomputedKey powers)
	{
		Debug.Assert(length is >= 0 and <= GcmFinalBlocks.MaxLength);

		if (length is 0)
		{
			return HashLengthBlock(accumulator, associatedDataBlock, lengthBlock, in powers);
		}

		EncryptCounters4(in aes, counter, 0, out Vector128<byte> c0, out Vector128<byte> c1, out Vector128<byte> c2, out Vector128<byte> c3);
		GcmFinalBlocks.Xor(ref c0, ref c1, ref c2, ref c3, ref input, ref output, length);
		return HashFinal(accumulator, associatedDataBlock, c0, c1, c2, c3, GcmFinalBlocks.GetBlockCount(length), lengthBlock, in powers);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void EncryptCounters4(in AesCipherX86 aes, Vector128<byte> counter, uint offset, out Vector128<byte> k0, out Vector128<byte> k1, out Vector128<byte> k2, out Vector128<byte> k3)
	{
		uint value = BinaryPrimitives.ReverseEndianness(counter.AsUInt32().GetElement(3)) + offset;
		Vector128<byte> prefix = Sse41.IsSupported ? counter : counter & Vector128.Create(uint.MaxValue, uint.MaxValue, uint.MaxValue, 0u).AsByte();
		k0 = CreateCounter(prefix, value);
		k1 = CreateCounter(prefix, value + 1u);
		k2 = CreateCounter(prefix, value + 2u);
		k3 = CreateCounter(prefix, value + 3u);
		aes.Encrypt4(ref k0, ref k1, ref k2, ref k3);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector128<byte> HashBlocks4(Vector128<byte> accumulator, Vector128<byte> associatedDataBlock, ref byte input, in GHashVector128PrecomputedKey powers)
	{
		MultiplyBlock(Vector128.LoadUnsafe(ref input), accumulator, in powers, 4, out Vector128<byte> lo, out Vector128<byte> hi);
		AccumulateBlock(Vector128.LoadUnsafe(ref input, 16), in powers, 3, ref lo, ref hi);
		AccumulateBlock(Vector128.LoadUnsafe(ref input, 32), in powers, 2, ref lo, ref hi);
		AccumulateBlock(Vector128.LoadUnsafe(ref input, 48), in powers, 1, ref lo, ref hi);
		AccumulateBlock(associatedDataBlock, in powers, 5, ref lo, ref hi);
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
