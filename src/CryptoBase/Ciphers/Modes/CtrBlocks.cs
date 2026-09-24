using CryptoBase.Ciphers.Blocks.Aes;

namespace CryptoBase.Ciphers.Modes;

internal static class CtrBlocks<TBlockCipher, TIncrementer>
	where TBlockCipher : IBlockEncryptor<TBlockCipher>
	where TIncrementer : struct, ICtrIncrementer
{
	private const int BlockSize = 16;

	internal static Vector128<byte> EncryptCounter(TBlockCipher blockCipher, ref Vector128<byte> counter)
	{
		Vector128<byte> stream = default;
		blockCipher.EncryptBlock(counter.AsReadOnlySpan(), stream.AsSpan());
		counter = TIncrementer.Inc(counter.ReverseEndianness128()).ReverseEndianness128();
		return stream;
	}

	internal static int XorBlocks(TBlockCipher blockCipher, ref Vector128<byte> counter, ReadOnlySpan<byte> source, Span<byte> destination)
	{
		if (source.Length >= 2 * BlockSize)
		{
			return XorBatch(blockCipher, ref counter, source, destination);
		}

		if (source.Length < BlockSize)
		{
			return 0;
		}

		XorFinalBlock(blockCipher, ref counter, source.Slice(0, BlockSize), destination);
		return BlockSize;
	}

	internal static void XorFinalBlock(TBlockCipher blockCipher, ref Vector128<byte> counter, ReadOnlySpan<byte> source, Span<byte> destination)
	{
		Vector128<byte> keyStream = default;

		try
		{
			keyStream = EncryptCounter(blockCipher, ref counter);

			if (source.Length is BlockSize)
			{
				(Vector128.LoadUnsafe(ref source.GetReference()) ^ keyStream).StoreUnsafe(ref destination.GetReference());
			}
			else
			{
				FastUtils.XorLess16(keyStream.AsReadOnlySpan(), source, destination, source.Length);
			}
		}
		finally
		{
			keyStream.ZeroMemory();
		}
	}

	[SkipLocalsInit]
	private static int XorBatch(TBlockCipher blockCipher, ref Vector128<byte> counter, ReadOnlySpan<byte> source, Span<byte> destination)
	{
		Span<byte> counters = stackalloc byte[2048];

		try
		{
			int offset = 0;

			while (source.Length - offset >= BlockSize)
			{
				int length = Math.Min(2048, source.Length - offset & -BlockSize);
				Vector128<byte> current = counter.ReverseEndianness128();
				int i = 0;

				if (Avx512BW.IsSupported)
				{
					Vector512<byte> lanes = TIncrementer.Add0123(Vector512.Create(Vector256.Create(current)));

					for (; i <= length - 64; i += 64)
					{
						lanes.ReverseEndianness128().StoreUnsafe(ref counters.GetReference(), (nuint)i);
						lanes = TIncrementer.Add4444(lanes);
					}

					current = lanes.GetLower().GetLower();
				}
				else if (Avx2.IsSupported)
				{
					Vector256<byte> lanes = TIncrementer.Add01(Vector256.Create(current));

					for (; i <= length - 32; i += 32)
					{
						lanes.ReverseEndianness128().StoreUnsafe(ref counters.GetReference(), (nuint)i);
						lanes = TIncrementer.Add22(lanes);
					}

					current = lanes.GetLower();
				}

				for (; i < length; i += BlockSize)
				{
					current.ReverseEndianness128().StoreUnsafe(ref counters.GetReference(), (nuint)i);
					current = TIncrementer.Inc(current);
				}

				counter = current.ReverseEndianness128();
				Span<byte> batch = counters.Slice(0, length);

				if (blockCipher is not AesCipher aes || !aes.TryEncryptXor(batch, source.Slice(offset), destination.Slice(offset)))
				{
					blockCipher.EncryptBlocks(batch, batch);
					FastUtils.Xor(batch, source.Slice(offset), destination.Slice(offset), length);
				}

				offset += length;
			}

			return offset;
		}
		finally
		{
			counters.Slice(0, Math.Min(counters.Length, source.Length & -BlockSize)).ZeroMemory();
		}
	}
}
