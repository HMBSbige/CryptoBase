namespace CryptoBase.SpeedTest.Workloads;

internal static class TestData
{
	/// <summary>
	/// Gets the bytes 0, 1, 2, … as a key or nonce, so that the two halves of an XTS key differ.
	/// </summary>
	public static byte[] Sequence(int length)
	{
		byte[] bytes = new byte[length];

		for (int i = 0; i < bytes.Length; ++i)
		{
			bytes[i] = (byte)i;
		}

		return bytes;
	}

	public static byte[] Random(int length)
	{
		return RandomNumberGenerator.GetBytes(length);
	}
}
