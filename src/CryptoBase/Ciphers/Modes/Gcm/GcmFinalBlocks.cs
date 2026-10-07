namespace CryptoBase.Ciphers.Modes.Gcm;

internal static class GcmFinalBlocks
{
	internal const int MaxLength = 4 * GHash.BlockSizeInBytes - 1;

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static int GetBlockCount(int length)
	{
		Debug.Assert(length is > 0 and <= MaxLength);
		return length + GHash.BlockSizeInBytes - 1 >> 4;
	}

	// During encryption, k0 to k3 retain the ciphertext blocks for GHASH.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static void Xor(ref Vector128<byte> k0, ref Vector128<byte> k1, ref Vector128<byte> k2, ref Vector128<byte> k3, ref byte input, ref byte output, int length)
	{
		int blockCount = GetBlockCount(length);
		int finalOffset = (blockCount - 1) * GHash.BlockSizeInBytes;
		int finalLength = length - finalOffset;

		if (blockCount > 1)
		{
			k0 ^= Vector128.LoadUnsafe(ref input);
			k0.StoreUnsafe(ref output);
		}

		if (blockCount > 2)
		{
			k1 ^= Vector128.LoadUnsafe(ref input, 16);
			k1.StoreUnsafe(ref output, 16);
		}

		if (blockCount > 3)
		{
			k2 ^= Vector128.LoadUnsafe(ref input, 32);
			k2.StoreUnsafe(ref output, 32);
		}

		Vector128<byte> finalKeyStream = blockCount switch
		{
			1 => k0,
			2 => k1,
			3 => k2,
			_ => k3
		};
		Vector128<byte> finalBlock = Vector128.LoadPartialUnsafe(ref input, (nuint)finalOffset, finalLength) ^ finalKeyStream;
		finalBlock.StorePartialUnsafe(ref output, (nuint)finalOffset, finalLength);
		finalBlock &= Vector128.LessThan(Vector128<byte>.Indices, Vector128.Create((byte)finalLength));

		switch (blockCount)
		{
			case 1:
			{
				k0 = finalBlock;
				break;
			}
			case 2:
			{
				k1 = finalBlock;
				break;
			}
			case 3:
			{
				k2 = finalBlock;
				break;
			}
			default:
			{
				k3 = finalBlock;
				break;
			}
		}
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static void Load(ref byte input, int length, out Vector128<byte> c0, out Vector128<byte> c1, out Vector128<byte> c2, out Vector128<byte> c3)
	{
		int blockCount = GetBlockCount(length);
		int finalOffset = (blockCount - 1) * GHash.BlockSizeInBytes;
		Vector128<byte> finalBlock = Vector128.LoadPartialUnsafe(ref input, (nuint)finalOffset, length - finalOffset);
		c0 = blockCount > 1 ? Vector128.LoadUnsafe(ref input) : finalBlock;
		c1 = blockCount > 2 ? Vector128.LoadUnsafe(ref input, 16) : finalBlock;
		c2 = blockCount > 3 ? Vector128.LoadUnsafe(ref input, 32) : finalBlock;
		c3 = finalBlock;
	}
}
