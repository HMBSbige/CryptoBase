namespace CryptoBase.Ciphers.Modes.Ctr;

internal static class CtrBlocks<TBlockCipher, TIncrementer>
	where TBlockCipher : IBlockEncryptor<TBlockCipher>
	where TIncrementer : struct, ICtrIncrementer
{
	private const int BlockSize = 16;

	[MethodImpl(MethodImplOptions.NoInlining)]
	internal static void Xor(TBlockCipher blockCipher, ref Vector128<byte> counter, ReadOnlySpan<byte> source, Span<byte> destination)
	{
		int processed = XorBlocks(blockCipher, ref counter, source, destination);
		int left = source.Length - processed;

		if (left is 0)
		{
			return;
		}

		XorBlock(blockCipher, ref counter, source.Slice(processed), destination.Slice(processed));
	}

	[MethodImpl(MethodImplOptions.NoInlining)]
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

		XorBlock(blockCipher, ref counter, source.Slice(0, BlockSize), destination);
		return BlockSize;
	}

	internal static void XorBlock(TBlockCipher blockCipher, ref Vector128<byte> counter, ReadOnlySpan<byte> source, Span<byte> destination)
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
	[MethodImpl(MethodImplOptions.NoInlining)]
	private static int XorBatch(TBlockCipher blockCipher, ref Vector128<byte> counter, ReadOnlySpan<byte> source, Span<byte> destination)
	{
		Unsafe.SkipInit(out InlineArray2048<byte> storage);
		Span<byte> counters = storage.AsSpan();

		try
		{
			int offset = 0;

			while (source.Length - offset >= BlockSize)
			{
				int length = Math.Min(counters.Length, source.Length - offset & -BlockSize);
				Span<byte> batch = counters.Slice(0, length);
				CtrCounters<TIncrementer>.Fill(ref counter, batch);

				if (!BlockModeDispatch.TryEncryptXor(blockCipher, batch, source.Slice(offset), destination.Slice(offset)))
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
