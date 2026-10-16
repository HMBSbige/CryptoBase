using CryptoBase.Ciphers.Blocks.Aes;
using static CryptoBase.Ciphers.Blocks.Aes.AesCipherArm;

namespace CryptoBase.Ciphers.Modes.Gcm;

internal static partial class AesGcmArm
{
	private const int WideThreshold = 128;

	[MethodImpl(MethodImplOptions.NoInlining)]
	internal static void Transform<TDirection>(in AesCipherArm aes, Vector128<byte> counter, ReadOnlySpan<byte> source, Span<byte> destination, ref GHashKey hashKey, ref Vector128<byte> accumulator, ref Vector128<byte> tagMask, Vector128<byte> associatedDataBlock, Vector128<byte> lengthBlock) where TDirection : struct, IBlockDirection
	{
		ref readonly GHashArmPrecomputedKey powers = ref hashKey.GetArm().Value;
		accumulator = AdvSimd.Arm64.ReverseElementBits(accumulator);
		int processed = 0;

		if (source.Length >= 64)
		{
			// The block kernels take no AAD block, so hash it first.
			accumulator ^= HashBlock(associatedDataBlock, in powers);
			associatedDataBlock = Vector128<byte>.Zero;
		}

		if (source.Length >= WideThreshold)
		{
			processed = Transform8<TDirection>(in aes, ref counter, source, destination, ref accumulator, in powers, ref tagMask);
		}
		else
		{
			tagMask = aes.Encrypt(tagMask);
		}

		if (source.Length - processed >= 64)
		{
			processed += Transform4<TDirection>(in aes, ref counter, source.Slice(processed), destination.Slice(processed), ref accumulator, in powers);
		}

		accumulator = TransformFinal<TDirection>(in aes, counter, ref Unsafe.Add(ref MemoryMarshal.GetReference(source), processed), ref Unsafe.Add(ref MemoryMarshal.GetReference(destination), processed), source.Length - processed, associatedDataBlock, lengthBlock, accumulator, in powers);
		accumulator = AdvSimd.Arm64.ReverseElementBits(accumulator);
	}

	[MethodImpl(MethodImplOptions.NoInlining)]
	internal static int Transform4<TDirection>(in AesCipherArm aes, ref Vector128<byte> counter, ReadOnlySpan<byte> source, Span<byte> destination, ref Vector128<byte> accumulator, in GHashArmPrecomputedKey powers) where TDirection : struct, IBlockDirection
	{
		int length = source.Length & -64;
		Debug.Assert(destination.Length >= length);

		if (length is 0)
		{
			return 0;
		}

		ref byte input = ref MemoryMarshal.GetReference(source);
		ref byte output = ref MemoryMarshal.GetReference(destination);
		ref readonly AesKeys roundKeys = ref aes.RoundKeys;
		uint value = BinaryPrimitives.ReadUInt32BigEndian(counter.AsReadOnlySpan().Slice(12));
		Vector128<uint> prefix = counter.AsUInt32().WithElement(3, 0U);
		Vector128<byte> c0 = default, c1 = default, c2 = default, c3 = default;

		if (!TDirection.IsDecrypt)
		{
			c0 = CreateCounter(prefix, value);
			c1 = CreateCounter(prefix, value + 1);
			c2 = CreateCounter(prefix, value + 2);
			c3 = CreateCounter(prefix, value + 3);
			value += 4;
			aes.Encrypt4(ref c0, ref c1, ref c2, ref c3);
			XorStore4Grouped(ref input, ref output, 0, ref c0, ref c1, ref c2, ref c3);
		}

		Vector128<byte> hash = accumulator;

		for (int offset = TDirection.IsDecrypt ? 0 : 64; offset < length; offset += 64)
		{
			if (TDirection.IsDecrypt)
			{
				c0 = Vector128.LoadUnsafe(ref input, (nuint)offset);
				c1 = Vector128.LoadUnsafe(ref input, (nuint)(offset + 16));
				c2 = Vector128.LoadUnsafe(ref input, (nuint)(offset + 32));
				c3 = Vector128.LoadUnsafe(ref input, (nuint)(offset + 48));
			}

			Vector128<byte> v0 = CreateCounter(prefix, value);
			Vector128<byte> v1 = CreateCounter(prefix, value + 1);
			Vector128<byte> v2 = CreateCounter(prefix, value + 2);
			Vector128<byte> v3 = CreateCounter(prefix, value + 3);
			value += 4;

			EncryptRound4(ref v0, ref v1, ref v2, ref v3, roundKeys.K0);
			GHashArm.GFMultiplyUnreduced(AdvSimd.Arm64.ReverseElementBits(c0) ^ hash, powers.Key4, out Vector128<ulong> low, out Vector128<ulong> high, out Vector128<ulong> middle);
			EncryptRound4(ref v0, ref v1, ref v2, ref v3, roundKeys.K1);
			EncryptRound4(ref v0, ref v1, ref v2, ref v3, roundKeys.K2);
			GHashArm.AccumulateProduct(AdvSimd.Arm64.ReverseElementBits(c1), powers.Key3, ref low, ref high, ref middle);
			EncryptRound4(ref v0, ref v1, ref v2, ref v3, roundKeys.K3);
			EncryptRound4(ref v0, ref v1, ref v2, ref v3, roundKeys.K4);
			GHashArm.AccumulateProduct(AdvSimd.Arm64.ReverseElementBits(c2), powers.Key2, ref low, ref high, ref middle);
			EncryptRound4(ref v0, ref v1, ref v2, ref v3, roundKeys.K5);
			EncryptRound4(ref v0, ref v1, ref v2, ref v3, roundKeys.K6);
			GHashArm.AccumulateProduct(AdvSimd.Arm64.ReverseElementBits(c3), powers.Key1, ref low, ref high, ref middle);
			EncryptRound4(ref v0, ref v1, ref v2, ref v3, roundKeys.K7);
			EncryptRound4(ref v0, ref v1, ref v2, ref v3, roundKeys.K8);
			hash = ReduceHash(low, high, middle);
			aes.EncryptFinalRounds4(ref v0, ref v1, ref v2, ref v3);

			c0 = v0;
			c1 = v1;
			c2 = v2;
			c3 = v3;
			XorStore4Grouped(ref input, ref output, (nuint)offset, ref c0, ref c1, ref c2, ref c3);
		}

		if (!TDirection.IsDecrypt)
		{
			GHashArm.GFMultiplyUnreduced(AdvSimd.Arm64.ReverseElementBits(c0) ^ hash, powers.Key4, out Vector128<ulong> finalLow, out Vector128<ulong> finalHigh, out Vector128<ulong> finalMiddle);
			GHashArm.AccumulateProduct(AdvSimd.Arm64.ReverseElementBits(c1), powers.Key3, ref finalLow, ref finalHigh, ref finalMiddle);
			GHashArm.AccumulateProduct(AdvSimd.Arm64.ReverseElementBits(c2), powers.Key2, ref finalLow, ref finalHigh, ref finalMiddle);
			GHashArm.AccumulateProduct(AdvSimd.Arm64.ReverseElementBits(c3), powers.Key1, ref finalLow, ref finalHigh, ref finalMiddle);
			hash = ReduceHash(finalLow, finalHigh, finalMiddle);
		}

		accumulator = hash;
		counter = CreateCounter(prefix, value);
		return length;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector128<byte> TransformFinal<TDirection>(in AesCipherArm aes, Vector128<byte> counter, ref byte input, ref byte output, int length, Vector128<byte> associatedDataBlock, Vector128<byte> lengthBlock, Vector128<byte> accumulator, in GHashArmPrecomputedKey powers) where TDirection : struct, IBlockDirection
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
	private static void EncryptCounters4(in AesCipherArm aes, Vector128<byte> counter, out Vector128<byte> k0, out Vector128<byte> k1, out Vector128<byte> k2, out Vector128<byte> k3)
	{
		uint value = BinaryPrimitives.ReverseEndianness(counter.AsUInt32().GetElement(3));
		Vector128<uint> prefix = counter.AsUInt32();
		k0 = counter;
		k1 = CreateCounter(prefix, value + 1);
		k2 = CreateCounter(prefix, value + 2);
		k3 = CreateCounter(prefix, value + 3);
		aes.Encrypt4(ref k0, ref k1, ref k2, ref k3);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector128<byte> HashBlock(Vector128<byte> block, in GHashArmPrecomputedKey powers)
	{
		GHashArm.GFMultiplyUnreduced(AdvSimd.Arm64.ReverseElementBits(block), powers.Key1, out Vector128<ulong> low, out Vector128<ulong> high, out Vector128<ulong> middle);
		return ReduceHash(low, high, middle);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector128<byte> HashLengthBlock(Vector128<byte> accumulator, Vector128<byte> associatedDataBlock, Vector128<byte> lengthBlock, in GHashArmPrecomputedKey powers)
	{
		GHashArm.GFMultiplyUnreduced(AdvSimd.Arm64.ReverseElementBits(lengthBlock) ^ accumulator, powers.Key1, out Vector128<ulong> low, out Vector128<ulong> high, out Vector128<ulong> middle);
		GHashArm.AccumulateProduct(AdvSimd.Arm64.ReverseElementBits(associatedDataBlock), powers.Key2, ref low, ref high, ref middle);
		return ReduceHash(low, high, middle);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector128<byte> HashFinal(Vector128<byte> accumulator, Vector128<byte> associatedDataBlock, Vector128<byte> c0, Vector128<byte> c1, Vector128<byte> c2, Vector128<byte> c3, int blockCount, Vector128<byte> lengthBlock, in GHashArmPrecomputedKey powers)
	{
		Vector128<ulong> low;
		Vector128<ulong> high;
		Vector128<ulong> middle;

		switch (blockCount)
		{
			case 1:
			{
				GHashArm.GFMultiplyUnreduced(AdvSimd.Arm64.ReverseElementBits(c0) ^ accumulator, powers.Key2, out low, out high, out middle);
				GHashArm.AccumulateProduct(AdvSimd.Arm64.ReverseElementBits(associatedDataBlock), powers.Key3, ref low, ref high, ref middle);
				break;
			}
			case 2:
			{
				GHashArm.GFMultiplyUnreduced(AdvSimd.Arm64.ReverseElementBits(c0) ^ accumulator, powers.Key3, out low, out high, out middle);
				GHashArm.AccumulateProduct(AdvSimd.Arm64.ReverseElementBits(c1), powers.Key2, ref low, ref high, ref middle);
				GHashArm.AccumulateProduct(AdvSimd.Arm64.ReverseElementBits(associatedDataBlock), powers.Key4, ref low, ref high, ref middle);
				break;
			}
			case 3:
			{
				GHashArm.GFMultiplyUnreduced(AdvSimd.Arm64.ReverseElementBits(c0) ^ accumulator, powers.Key4, out low, out high, out middle);
				GHashArm.AccumulateProduct(AdvSimd.Arm64.ReverseElementBits(c1), powers.Key3, ref low, ref high, ref middle);
				GHashArm.AccumulateProduct(AdvSimd.Arm64.ReverseElementBits(c2), powers.Key2, ref low, ref high, ref middle);
				GHashArm.AccumulateProduct(AdvSimd.Arm64.ReverseElementBits(associatedDataBlock), powers.Key5, ref low, ref high, ref middle);
				break;
			}
			default:
			{
				GHashArm.GFMultiplyUnreduced(AdvSimd.Arm64.ReverseElementBits(c0) ^ accumulator, powers.Key5, out low, out high, out middle);
				GHashArm.AccumulateProduct(AdvSimd.Arm64.ReverseElementBits(c1), powers.Key4, ref low, ref high, ref middle);
				GHashArm.AccumulateProduct(AdvSimd.Arm64.ReverseElementBits(c2), powers.Key3, ref low, ref high, ref middle);
				GHashArm.AccumulateProduct(AdvSimd.Arm64.ReverseElementBits(c3), powers.Key2, ref low, ref high, ref middle);
				GHashArm.AccumulateProduct(AdvSimd.Arm64.ReverseElementBits(associatedDataBlock), powers.Key6, ref low, ref high, ref middle);
				break;
			}
		}

		GHashArm.AccumulateProduct(AdvSimd.Arm64.ReverseElementBits(lengthBlock), powers.Key1, ref low, ref high, ref middle);
		return ReduceHash(low, high, middle);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector128<byte> CreateCounter(Vector128<uint> prefix, uint value)
	{
		return prefix.WithElement(3, BinaryPrimitives.ReverseEndianness(value)).AsByte();
	}

	// Keep stores grouped so the first batch can use paired stores.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void XorStore4Grouped(ref byte input, ref byte output, nuint offset, ref Vector128<byte> v0, ref Vector128<byte> v1, ref Vector128<byte> v2, ref Vector128<byte> v3)
	{
		v0 ^= Vector128.LoadUnsafe(ref input, offset);
		v1 ^= Vector128.LoadUnsafe(ref input, offset + 16);
		v2 ^= Vector128.LoadUnsafe(ref input, offset + 32);
		v3 ^= Vector128.LoadUnsafe(ref input, offset + 48);
		v0.StoreUnsafe(ref output, offset);
		v1.StoreUnsafe(ref output, offset + 16);
		v2.StoreUnsafe(ref output, offset + 32);
		v3.StoreUnsafe(ref output, offset + 48);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector128<byte> ReduceHash(Vector128<ulong> low, Vector128<ulong> high, Vector128<ulong> middle)
	{
		GHashArm.AssembleProduct(low, high, middle, out Vector128<uint> productLow, out Vector128<uint> productHigh);
		return GHashArm.Reduce(productLow, productHigh);
	}
}
