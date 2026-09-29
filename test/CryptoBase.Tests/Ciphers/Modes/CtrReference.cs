using System.Buffers.Binary;

namespace CryptoBase.Tests.Ciphers.Modes;

internal static class CtrReference
{
	// Only the low counterBits bits advance and wrap; the remaining high bits stay fixed.
	internal static byte[] Transform(byte[] initialCounter, byte[] source, Func<byte[], byte[]> encryptCounters, int counterBits = 128)
	{
		byte[] counters = new byte[source.Length + 15 & -16];
		UInt128 counter = BinaryPrimitives.ReadUInt128BigEndian(initialCounter);
		UInt128 counterMask = counterBits is 128 ? UInt128.MaxValue : (UInt128.One << counterBits) - 1;

		for (int offset = 0; offset < counters.Length; offset += 16)
		{
			BinaryPrimitives.WriteUInt128BigEndian(counters.AsSpan(offset, 16), counter);
			counter = counter & ~counterMask | counter + 1 & counterMask;
		}

		byte[] mask = encryptCounters(counters);
		byte[] output = new byte[source.Length];

		for (int i = 0; i < source.Length; ++i)
		{
			output[i] = (byte)(source[i] ^ mask[i]);
		}

		return output;
	}
}
