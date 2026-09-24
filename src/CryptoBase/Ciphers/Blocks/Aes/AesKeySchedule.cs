namespace CryptoBase.Ciphers.Blocks.Aes;

internal static class AesKeySchedule
{
	internal const byte Rcon0 = 0x00;
	internal const byte Rcon1 = 0x01;
	internal const byte Rcon2 = 0x02;
	internal const byte Rcon3 = 0x04;
	internal const byte Rcon4 = 0x08;
	internal const byte Rcon5 = 0x10;
	internal const byte Rcon6 = 0x20;
	internal const byte Rcon7 = 0x40;
	internal const byte Rcon8 = 0x80;
	internal const byte Rcon9 = 0x1b;
	internal const byte Rcon10 = 0x36;

	private static ReadOnlySpan<byte> Rcon => [Rcon0, Rcon1, Rcon2, Rcon3, Rcon4, Rcon5, Rcon6, Rcon7, Rcon8, Rcon9, Rcon10];

	internal static int GetRounds(int keyLength)
	{
		return keyLength switch
		{
			16 => 10,
			24 => 12,
			32 => 14,
			_ => ThrowHelper.ThrowArgumentOutOfRangeException<int>("key", "Key length must be 16/24/32 bytes")
		};
	}

	internal static int Expand<TSubWord>(ReadOnlySpan<byte> key, Span<uint> words) where TSubWord : IAesSubWord
	{
		int rounds = GetRounds(key.Length);
		int nk = key.Length / sizeof(uint);
		int wordCount = (rounds + 1) * 4;
		words = words.Slice(0, wordCount);

		for (int i = 0; i < nk; ++i)
		{
			words[i] = BinaryPrimitives.ReadUInt32LittleEndian(key.Slice(i * sizeof(uint)));
		}

		uint t = words[nk - 1];

		for (int i = nk, round = 1; i < words.Length; i += nk, ++round)
		{
			int count = Math.Min(nk, words.Length - i);
			ReadOnlySpan<uint> previous = words.Slice(i - nk, count);
			Span<uint> current = words.Slice(i, count);
			t = TSubWord.SubWord(t).RotateRight(8) ^ Rcon[round];

			for (int j = 0; j < current.Length; ++j)
			{
				if (nk is 8 && j is 4)
				{
					t = TSubWord.SubWord(t);
				}

				t ^= previous[j];
				current[j] = t;
			}
		}

		return rounds;
	}
}
