namespace CryptoBase.Tests.Kdf;

internal static class KdfTestUtils
{
	internal static byte[] CreateData(int length, int seed)
	{
		byte[] data = new byte[length];

		for (int i = 0; i < data.Length; ++i)
		{
			data[i] = (byte)(seed + i * 31 + (i >> 1));
		}

		return data;
	}

	internal static byte[] CreateOverlapBuffer(ReadOnlySpan<byte> source, int sourceOffset, int destinationOffset, int destinationLength)
	{
		byte[] buffer = new byte[Math.Max(sourceOffset + source.Length, destinationOffset + destinationLength)];
		source.CopyTo(buffer.AsSpan(sourceOffset));
		return buffer;
	}
}
