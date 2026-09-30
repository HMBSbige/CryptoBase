using CryptoBase.Ciphers.Blocks.SM4;
using CryptoBase.Ciphers.Modes;
using CryptoBase.Ciphers.Modes.Ctr;
using CryptoBase.Tests.Ciphers.Modes;
using System.Buffers.Binary;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.X86;
using static CryptoBase.Tests.TestUtils;

namespace CryptoBase.Tests.Ciphers.Blocks.SM4;

public class SM4GfniTest
{
	[Before(Class)]
	public static void SkipWhenUnavailable()
	{
		if (!SM4Gfni.IsSupported)
		{
			Skip.Test("GFNI is required.");
		}
	}

	[Test]
	[Arguments(4)]
	[Arguments(8)]
	[Arguments(16)]
	[Arguments(32)]
	[Arguments(64)]
	public Task PartialAndFullBatchesMatchIndependentReference(int width)
	{
		return SM4KernelTestUtils.BatchesMatchIndependentReference<SM4Gfni>(width);
	}

	[Test]
	public Task Sbox128CoversEveryByteValueInEveryPosition()
	{
		return SM4KernelTestUtils.Substitute128MatchesIndependentReference(SM4Gfni.Substitute);
	}

	[Test]
	public Task Sbox256CoversEveryByteValueInEveryPosition()
	{
		if (!Gfni.V256.IsSupported)
		{
			Skip.Test("GFNI with 256-bit vectors is required.");
		}

		return SM4KernelTestUtils.Substitute256MatchesIndependentReference(SM4Gfni.Substitute);
	}

	[Test]
	public Task Sbox512CoversEveryByteValueInEveryPosition()
	{
		if (!Gfni.V512.IsSupported)
		{
			Skip.Test("GFNI with 512-bit vectors is required.");
		}

		return SM4KernelTestUtils.Substitute512MatchesIndependentReference(SM4Gfni.Substitute);
	}

	[Test]
	[MatrixDataSource]
	public async Task Ctr32WrapsWithoutChangingNonce([Matrix(2u, 0xFFFFFFF1u, 0xFFFFFFF5u, 0xFFFFFFC0u)] uint initialCounter, [Matrix(1024, 2048, 4096)] int length)
	{
		if (!SM4Gfni.SupportsModePolicy)
		{
			Skip.Test("GFNI with 256-bit vectors is required.");
		}

		byte[] key = CreateDeterministicSource(16);
		byte[] initial = CreateDeterministicSource(16);
		BinaryPrimitives.WriteUInt32BigEndian(initial.AsSpan(12), initialCounter);
		using SM4Cipher cipher = SM4Cipher.Create(key);

		byte[] plaintext = CreateDeterministicSource(length);
		byte[] expected = CtrReference.Transform(initial, plaintext, counters => SM4Reference.Transform(key, counters), 32);

		foreach (bool inPlace in new[] { false, true })
		{
			byte[] output = CreateGuardedBuffer(3, length);
			plaintext.CopyTo(output, 3);
			Vector128<byte> counter = Vector128.Create(initial);
			int processed = BlockModeDispatch.XorCtr<SM4Cipher, CtrIncrementer32>(cipher, ref counter, inPlace ? output.AsSpan(3, length) : plaintext, output.AsSpan(3, length));
			await Assert.That(processed).IsEqualTo(length);
			await AssertOutput(output, 3, expected);
			byte[] expectedCounter = (byte[])initial.Clone();
			BinaryPrimitives.WriteUInt32BigEndian(expectedCounter.AsSpan(12), initialCounter + (uint)(length / 16));
			await Assert.That(counter).IsEqualTo(Vector128.Create(expectedCounter));
		}
	}
}
