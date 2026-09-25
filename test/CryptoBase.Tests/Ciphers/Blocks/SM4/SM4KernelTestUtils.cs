using CryptoBase.Ciphers.Blocks.SM4;
using System.Runtime.Intrinsics;

namespace CryptoBase.Tests.Ciphers.Blocks.SM4;

internal static class SM4KernelTestUtils
{
	public static async Task BatchesMatchIndependentReference<TKernel>(int width) where TKernel : struct, ISM4Kernel
	{
		if (width > TKernel.MaxBlocks)
		{
			Skip.Test($"The current instruction set supports at most {TKernel.MaxBlocks} blocks.");
		}

		Random random = new(0x534D3400 + width);

		for (int count = 1; count <= width; ++count)
		{
			for (int sample = 0; sample < 4; ++sample)
			{
				byte[] key = new byte[16];
				byte[] input = new byte[count * 16];
				random.NextBytes(key);
				random.NextBytes(input);
				uint[] roundKeys = new uint[32];
				SM4KeySchedule.InitRoundKeys(ref key[0], ref roundKeys[0]);
				int sourceOffset = sample * 7 % 15 + 1;
				int destinationOffset = 16 - sourceOffset;
				byte[] source = TestUtils.CreateGuardedBuffer(sourceOffset, input.Length);
				input.CopyTo(source, sourceOffset);
				byte[] destination = TestUtils.CreateGuardedBuffer(destinationOffset, input.Length);

				for (int direction = 0; direction < 2; ++direction)
				{
					byte[] expected = SM4Reference.Transform(key, input, direction is 1);
					TestUtils.PrepareDestination(destination);
					TKernel.Process(width, count, ref roundKeys[0], ref source[sourceOffset], ref destination[destinationOffset]);
					await TestUtils.AssertOutput(destination, destinationOffset, expected);
					await TestUtils.AssertOutput(source, sourceOffset, input);

					input.CopyTo(destination, destinationOffset);
					TKernel.Process(width, count, ref roundKeys[0], ref destination[destinationOffset], ref destination[destinationOffset]);
					await TestUtils.AssertOutput(destination, destinationOffset, expected);
					Array.Reverse(roundKeys);
				}
			}
		}
	}

	public static async Task Substitute128MatchesIndependentReference(Func<Vector128<byte>, Vector128<byte>> substitute)
	{
		uint[] inputs = CreateSboxInputs();
		uint[] actual = new uint[inputs.Length];

		for (int offset = 0; offset < inputs.Length; offset += Vector128<uint>.Count)
		{
			substitute(Vector128.LoadUnsafe(ref inputs[offset]).AsByte()).AsUInt32().StoreUnsafe(ref actual[offset]);
		}

		await Assert.That(actual).IsEquivalentTo(inputs.Select(SM4Reference.Substitute), CollectionOrdering.Matching);
	}

	public static async Task Substitute256MatchesIndependentReference(Func<Vector256<byte>, Vector256<byte>> substitute)
	{
		uint[] inputs = CreateSboxInputs();
		uint[] actual = new uint[inputs.Length];

		for (int offset = 0; offset < inputs.Length; offset += Vector256<uint>.Count)
		{
			substitute(Vector256.LoadUnsafe(ref inputs[offset]).AsByte()).AsUInt32().StoreUnsafe(ref actual[offset]);
		}

		await Assert.That(actual).IsEquivalentTo(inputs.Select(SM4Reference.Substitute), CollectionOrdering.Matching);
	}

	private static uint[] CreateSboxInputs()
	{
		ReadOnlySpan<uint> backgrounds = [0, uint.MaxValue, 0xA55A3CC3, 0x10204080, 0x01234567, 0x89ABCDEF, 0x76543210, 0xFEDCBA98];
		uint[] inputs = new uint[4 * 256 * backgrounds.Length];

		for (int position = 0; position < 4; ++position)
		{
			for (uint value = 0; value < 256; ++value)
			{
				for (int lane = 0; lane < backgrounds.Length; ++lane)
				{
					// Distinct lane values expose byte-permutation errors.
					uint laneValue = value + (uint)lane * 17 & 255;
					inputs[(position * 256 + (int)value) * backgrounds.Length + lane] = backgrounds[lane] & ~(255u << position * 8) | laneValue << position * 8;
				}
			}
		}

		return inputs;
	}
}
