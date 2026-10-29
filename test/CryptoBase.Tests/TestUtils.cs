using CryptoBase.Abstractions.Ciphers;
using System.Diagnostics;
using System.Formats.Asn1;
using System.Reflection;

namespace CryptoBase.Tests;

public static class TestUtils
{
	public const byte DestinationSentinel = 0xA5;

	public static byte[] CreateDeterministicSource(int length)
	{
		byte[] source = new byte[length];

		for (int i = 0; i < source.Length; ++i)
		{
			source[i] = (byte)(i * 131 + length * 17 + 7);
		}

		return source;
	}

	public static byte[] Concat(ReadOnlySpan<byte> first, ReadOnlySpan<byte> second)
	{
		byte[] result = new byte[first.Length + second.Length];
		first.CopyTo(result);
		second.CopyTo(result.AsSpan().Slice(first.Length));
		return result;
	}

	public static byte[] Flip(byte[] source, int index)
	{
		byte[] flipped = (byte[])source.Clone();
		flipped[index] ^= (byte)(1 << index % 8);
		return flipped;
	}

	public static void PrepareDestination(Span<byte> destination)
	{
		destination.Fill(DestinationSentinel);
	}

	public static bool ConsumePendingInterrupt()
	{
		try
		{
			Thread.Sleep(0);
			return false;
		}
		catch (ThreadInterruptedException)
		{
			return true;
		}
	}

	public static void SkipUnlessOptimized<T>()
	{
		if (typeof(T).Assembly.GetCustomAttribute<DebuggableAttribute>()?.IsJITOptimizerDisabled is true)
		{
			Skip.Test("The implementation is not optimized.");
		}
	}

	public static void SkipUnlessSupported(IKernelCase kernel)
	{
		if (!kernel.IsSupported)
		{
			Skip.Test($"{kernel} is not supported here.");
		}
	}

	public static Type[] ImplementationsOf(Type interfaceType)
	{
		return interfaceType.Assembly.GetTypes().Where(type => type is { IsInterface: false, IsAbstract: false } && type.IsAssignableTo(interfaceType)).ToArray();
	}

	public static byte[] CreateGuardedBuffer(int offset, int length, int tailLength = 11)
	{
		byte[] buffer = new byte[offset + length + tailLength];
		PrepareDestination(buffer);
		return buffer;
	}

	public static byte[] CreateGuardedBuffer(int offset, ReadOnlySpan<byte> payload)
	{
		byte[] buffer = CreateGuardedBuffer(offset, payload.Length);
		payload.CopyTo(buffer.AsSpan().Slice(offset));
		return buffer;
	}

	public static byte[] ShortBuffer(int length, int shortfall)
	{
		return CreateGuardedBuffer(0, Math.Max(0, length - shortfall), 0);
	}

	public static byte[] Resize(byte[] source, int delta)
	{
		byte[] resized = new byte[source.Length + delta];
		source.AsSpan(0, Math.Min(source.Length, resized.Length)).CopyTo(resized);
		return resized;
	}

	// A DER TLV with a one-byte tag around the concatenated contents.
	public static byte[] Tlv(byte tag, params byte[][] contents)
	{
		int length = contents.Sum(static content => content.Length);
		List<byte> encoded = [tag];

		if (length < 0x80)
		{
			encoded.Add((byte)length);
		}
		else
		{
			byte[] lengthBytes = BitConverter.GetBytes(length).Reverse().SkipWhile(static value => value is 0).ToArray();
			encoded.Add((byte)(0x80 | lengthBytes.Length));
			encoded.AddRange(lengthBytes);
		}

		foreach (byte[] content in contents)
		{
			encoded.AddRange(content);
		}

		return [.. encoded];
	}

	public static byte[] Sequence(params byte[][] contents)
	{
		return Tlv(0x30, contents);
	}

	public static byte[] Oid(string oid)
	{
		AsnWriter writer = new(AsnEncodingRules.DER);
		writer.WriteObjectIdentifier(oid);
		return writer.Encode();
	}

	public static async Task AssertOutput(byte[] destination, byte[] expected, int written)
	{
		using (Assert.Multiple())
		{
			await Assert.That(written).IsEqualTo(expected.Length);
			await AssertOutputCore(destination, expected);
		}
	}

	public static Task AssertOutput(byte[] destination, byte[] expected)
	{
		return AssertOutput(destination, 0, expected);
	}

	public static async Task AssertOutput(byte[] destination, int offset, byte[] expected)
	{
		using (Assert.Multiple())
		{
			await AssertOutputCore(destination, expected, offset);
		}
	}

	public static async Task AssertWrites(byte[] expected, Action<Span<byte>> write)
	{
		byte[] destination = new byte[expected.Length + 2];
		PrepareDestination(destination);
		write(destination.AsSpan(1, expected.Length));
		await AssertOutput(destination, 1, expected);
	}

	private static async Task AssertOutputCore(byte[] destination, byte[] expected, int offset = 0)
	{
		await Assert.That(destination.AsMemory(offset, expected.Length)).IsEquivalentTo(expected, CollectionOrdering.Matching);
		await Assert.That(destination.AsMemory(0, offset)).All(static value => value is DestinationSentinel);
		await Assert.That(destination.AsMemory(offset + expected.Length)).All(static value => value is DestinationSentinel);
	}

	public static async Task VerifyStreamVector(IStreamCipher crypto, byte[] source, byte[] expected)
	{
		using (crypto)
		{
			byte[] actual = new byte[source.Length];
			crypto.Xor(source, actual);
			await Assert.That(actual).IsEquivalentTo(expected, CollectionOrdering.Matching);
		}
	}
}
