using System.Buffers.Binary;

namespace CryptoBase.Tests.Ciphers.Modes;

// IEEE 1619 XTS with ciphertext stealing; transformBlock applies the data key in the requested direction.
internal static class XtsReference
{
	internal static byte[] Transform(byte[] encryptedTweak, byte[] source, bool decrypt, Func<byte[], byte[]> transformBlock)
	{
		UInt128 tweak = BinaryPrimitives.ReadUInt128LittleEndian(encryptedTweak);
		byte[] output = new byte[source.Length];
		int tail = source.Length % 16;
		int ordinaryLength = tail is 0 ? source.Length : source.Length - tail - 16;
		int offset = 0;

		for (; offset < ordinaryLength; offset += 16, tweak = MultiplyByAlpha(tweak))
		{
			XexBlock(transformBlock, tweak, source.AsSpan(offset, 16), output.AsSpan(offset, 16));
		}

		if (tail is not 0)
		{
			UInt128 nextTweak = MultiplyByAlpha(tweak);
			Span<byte> complete = stackalloc byte[16];
			// CTS first recovers/produces the stolen block, then reconstructs its full input.
			XexBlock(transformBlock, decrypt ? nextTweak : tweak, source.AsSpan(offset, 16), complete);
			complete.Slice(0, tail).CopyTo(output.AsSpan(offset + 16));
			source.AsSpan(offset + 16).CopyTo(complete);
			XexBlock(transformBlock, decrypt ? tweak : nextTweak, complete, output.AsSpan(offset, 16));
		}

		return output;
	}

	private static void XexBlock(Func<byte[], byte[]> transformBlock, UInt128 tweak, ReadOnlySpan<byte> source, Span<byte> destination)
	{
		byte[] block = new byte[16];
		BinaryPrimitives.WriteUInt128LittleEndian(block, BinaryPrimitives.ReadUInt128LittleEndian(source) ^ tweak);
		BinaryPrimitives.WriteUInt128LittleEndian(destination, BinaryPrimitives.ReadUInt128LittleEndian(transformBlock(block)) ^ tweak);
	}

	private static UInt128 MultiplyByAlpha(UInt128 value)
	{
		return value << 1 ^ (value >> 127) * 0x87u;
	}
}
