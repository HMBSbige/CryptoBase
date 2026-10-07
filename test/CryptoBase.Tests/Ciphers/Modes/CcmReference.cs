namespace CryptoBase.Tests.Ciphers.Modes;

// NIST SP 800-38C formatting, counter generation and CBC-MAC for any valid nonce and tag length.
internal static class CcmReference
{
	internal static (byte[] Ciphertext, byte[] Tag) Encrypt(Func<byte[], byte[]> encryptBlocks, byte[] nonce, byte[] plaintext, byte[] associatedData, int tagLength = 16)
	{
		int lengthSize = 15 - nonce.Length;
		List<byte> counters = [];

		for (int i = 0; i <= (plaintext.Length + 15) / 16; ++i)
		{
			counters.Add((byte)(lengthSize - 1));
			counters.AddRange(nonce);
			counters.AddRange(ToBigEndian((ulong)i, lengthSize));
		}

		byte[] keyStream = encryptBlocks([.. counters]);
		byte[] ciphertext = new byte[plaintext.Length];

		for (int i = 0; i < plaintext.Length; ++i)
		{
			ciphertext[i] = (byte)(plaintext[i] ^ keyStream[16 + i]);
		}

		byte[] formatted = Format(nonce, plaintext, associatedData, tagLength);
		byte[] mac = new byte[16];

		for (int offset = 0; offset < formatted.Length; offset += 16)
		{
			for (int i = 0; i < mac.Length; ++i)
			{
				mac[i] ^= formatted[offset + i];
			}

			mac = encryptBlocks(mac);
		}

		byte[] tag = new byte[tagLength];

		for (int i = 0; i < tag.Length; ++i)
		{
			tag[i] = (byte)(mac[i] ^ keyStream[i]);
		}

		return (ciphertext, tag);
	}

	private static byte[] Format(byte[] nonce, byte[] plaintext, byte[] associatedData, int tagLength)
	{
		int lengthSize = 15 - nonce.Length;
		List<byte> formatted =
		[
			(byte)((associatedData.Length > 0 ? 0x40 : 0) | (tagLength - 2) / 2 << 3 | lengthSize - 1), .. nonce,
			.. ToBigEndian((ulong)plaintext.Length, lengthSize)
		];

		if (associatedData.Length > 0)
		{
			if (associatedData.Length < 0xFF00)
			{
				formatted.AddRange(ToBigEndian((ulong)associatedData.Length, 2));
			}
			else
			{
				formatted.Add(0xFF);
				formatted.Add(0xFE);
				formatted.AddRange(ToBigEndian((ulong)associatedData.Length, 4));
			}

			formatted.AddRange(associatedData);
			PadToBlock(formatted);
		}

		formatted.AddRange(plaintext);
		PadToBlock(formatted);
		return [.. formatted];
	}

	private static void PadToBlock(List<byte> formatted)
	{
		while (formatted.Count % 16 is not 0)
		{
			formatted.Add(0);
		}
	}

	private static byte[] ToBigEndian(ulong value, int length)
	{
		byte[] result = new byte[length];

		for (int i = length - 1; i >= 0; --i)
		{
			result[i] = (byte)value;
			value >>= 8;
		}

		return result;
	}
}
