using CryptoBase.Ciphers.Blocks.SM4;
using System.Buffers.Binary;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace CryptoBase.Tests.Ciphers.Blocks.SM4;

public class SM4BlockDriverTest
{
	public static IEnumerable<(int Maximum, int Blocks, bool SingleBlock)> Cases()
	{
		foreach (int maximum in new[] { 4, 8, 16, 32, 64 })
		{
			for (int blocks = 0; blocks <= 130; ++blocks)
			{
				yield return (maximum, blocks, false);
			}

			yield return (maximum, 1, true);
		}
	}

	[Test]
	[MethodDataSource(nameof(Cases))]
	public Task UsesFullBatchesAndTheSmallestTailWidth(int maximum, int blocks, bool singleBlock)
	{
		return maximum switch
		{
			4 => Verify<Kernel4>(blocks, singleBlock),
			8 => Verify<Kernel8>(blocks, singleBlock),
			16 => Verify<Kernel16>(blocks, singleBlock),
			32 => Verify<Kernel32>(blocks, singleBlock),
			64 => Verify<Kernel64>(blocks, singleBlock),
			_ => throw new ArgumentOutOfRangeException(nameof(maximum))
		};
	}

	private static async Task Verify<TKernel>(int blocks, bool singleBlock) where TKernel : struct, ISM4Kernel
	{
		int maximum = TKernel.MaxBlocks;
		int sourceOffset = blocks % 15 + 1;
		int destinationOffset = 16 - sourceOffset;
		byte[] input = TestUtils.CreateDeterministicSource(blocks * 16);
		byte[] source = TestUtils.CreateGuardedBuffer(sourceOffset, input.Length, maximum * 16 + 11);
		byte[] destination = TestUtils.CreateGuardedBuffer(destinationOffset, input.Length, maximum * 16 + 11);

		for (int block = 0; block < blocks; ++block)
		{
			BinaryPrimitives.WriteUInt32LittleEndian(input.AsSpan().Slice(block * 16), (uint)block);
			BinaryPrimitives.WriteUInt32LittleEndian(destination.AsSpan().Slice(destinationOffset + block * 16), (uint)block);
		}

		input.CopyTo(source, sourceOffset);
		uint[] recorded = new uint[2 + (blocks + 1) * 4];
		recorded[1] = (uint)blocks + 1;
		SM4BlockDriver<TKernel>.ProcessBlocks(ref recorded[0], source.AsSpan().Slice(sourceOffset, input.Length), destination.AsSpan().Slice(destinationOffset), singleBlock);

		List<uint> expected = [];
		int fullBatches = blocks / maximum;

		for (int batch = 0; batch < fullBatches; ++batch)
		{
			expected.AddRange([(uint)maximum, (uint)maximum, (uint)(batch * maximum), (uint)(batch * maximum)]);
		}

		int remaining = blocks % maximum;

		if (remaining > 0)
		{
			int width = 4;

			while (width < remaining)
			{
				width *= 2;
			}

			expected.AddRange([(uint)width, (uint)remaining, (uint)(blocks - remaining), (uint)(blocks - remaining)]);
		}

		await Assert.That(recorded[0]).IsEqualTo((uint)(expected.Count / 4));
		await Assert.That(recorded.AsMemory(2, expected.Count)).IsEquivalentTo(expected, CollectionOrdering.Matching);
		await TestUtils.AssertOutput(destination, destinationOffset, input);
		await TestUtils.AssertOutput(source, sourceOffset, input);
	}

	private static void RecordAndCopy(int maximum, int width, int count, ref uint rk, ref byte source, ref byte destination)
	{
		if (width < 4 || width > maximum || (width & width - 1) is not 0 || count < 1 || count > width)
		{
			throw new InvalidOperationException($"Invalid kernel batch: maximum={maximum}, width={width}, count={count}.");
		}

		if (rk >= Unsafe.Add(ref rk, 1))
		{
			throw new InvalidOperationException("The driver made more calls than there are input blocks.");
		}

		Span<uint> record = MemoryMarshal.CreateSpan(ref Unsafe.Add(ref rk, 2 + (int)rk * 4), 4);
		ReadOnlySpan<byte> input = MemoryMarshal.CreateReadOnlySpan(ref source, count * 16);
		Span<byte> output = MemoryMarshal.CreateSpan(ref destination, count * 16);
		record[0] = (uint)width;
		record[1] = (uint)count;
		record[2] = BinaryPrimitives.ReadUInt32LittleEndian(input);
		record[3] = BinaryPrimitives.ReadUInt32LittleEndian(output);
		input.CopyTo(output);
		++rk;
	}

	private readonly struct Kernel4 : ISM4Kernel
	{
		public static bool IsSupported => true;

		public static int MaxBlocks => 4;

		public static void Process(int width, int count, ref uint rk, ref byte source, ref byte destination)
		{
			RecordAndCopy(MaxBlocks, width, count, ref rk, ref source, ref destination);
		}
	}

	private readonly struct Kernel8 : ISM4Kernel
	{
		public static bool IsSupported => true;

		public static int MaxBlocks => 8;

		public static void Process(int width, int count, ref uint rk, ref byte source, ref byte destination)
		{
			RecordAndCopy(MaxBlocks, width, count, ref rk, ref source, ref destination);
		}
	}

	private readonly struct Kernel16 : ISM4Kernel
	{
		public static bool IsSupported => true;

		public static int MaxBlocks => 16;

		public static void Process(int width, int count, ref uint rk, ref byte source, ref byte destination)
		{
			RecordAndCopy(MaxBlocks, width, count, ref rk, ref source, ref destination);
		}
	}

	private readonly struct Kernel32 : ISM4Kernel
	{
		public static bool IsSupported => true;

		public static int MaxBlocks => 32;

		public static void Process(int width, int count, ref uint rk, ref byte source, ref byte destination)
		{
			RecordAndCopy(MaxBlocks, width, count, ref rk, ref source, ref destination);
		}
	}

	private readonly struct Kernel64 : ISM4Kernel
	{
		public static bool IsSupported => true;

		public static int MaxBlocks => 64;

		public static void Process(int width, int count, ref uint rk, ref byte source, ref byte destination)
		{
			RecordAndCopy(MaxBlocks, width, count, ref rk, ref source, ref destination);
		}
	}
}
