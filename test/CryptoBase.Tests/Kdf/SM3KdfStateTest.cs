using CryptoBase.Internal;
using CryptoBase.Kdf;
using System.Buffers.Binary;
using static CryptoBase.Tests.SM2.SM2TestUtils;

namespace CryptoBase.Tests.Kdf;

public class SM3KdfStateTest
{
	// Keys around the 32-byte blocks, from Z around the 64-byte blocks of SM3, against the KDF of GB/T 32918.4-2016, Sec. 5.4.3 written out with SM3.
	[Test]
	public async Task KeysMatchTheDefinition()
	{
		Random random = new(1);
		List<string> failures = [];

		foreach (int zLength in (int[])[0, 1, 55, 56, 59, 60, 64, 65, 128, 200])
		{
			byte[] z = new byte[zLength];
			random.NextBytes(z);

			foreach (int length in (int[])[0, 1, 16, 31, 32, 33, 64, 65, 1000])
			{
				byte[] key = new byte[length];
				Derive(z, key);

				if (!key.AsSpan().SequenceEqual(ReferenceKdf(z, length)))
				{
					failures.Add($"Z of {zLength} bytes, a key of {length} bytes");
				}
			}
		}

		await Assert.That(failures).IsEmpty();
	}

	// t of GB/T 32918.5-2017, Sec. C.2, from x2 ‖ y2.
	[Test]
	public async Task KeyOfAnnexC()
	{
		byte[] key = new byte[19];
		Derive(Hex("335E18D7 51E51F04 0E27D468 138B7AB1 DC86AD7F 981D7D41 6222FD6A B3ED230D AB743EBC FB22D64F 7B6AB791 F70658F2 5B48FA93 E54064FD BFBED3F0 BD847AC9"), key);

		await Assert.That(key).IsEquivalentTo(Hex("44E60FDB F0BAE814 37665374 BEF26749 046C9E"), CollectionOrdering.Matching);
	}

	// Z absorbed in parts gives the key of Z whole; a block of any counter is SM3(Z ‖ ct), and Z may lie in the output.
	[Test]
	public async Task PartsBlocksAndOverlapMatch()
	{
		byte[] z = [.. Enumerable.Range(0, 150).Select(static i => (byte)i)];
		byte[] expected = ReferenceKdf(z, 100);
		SM3KdfState kdf = default;
		kdf.Initialize();
		kdf.Append(z.AsSpan(0, 7));
		kdf.Append(z.AsSpan(7, 70));
		kdf.Append(z.AsSpan(77));
		byte[] key = new byte[100];
		kdf.Derive(key);
		byte[] block = new byte[32];
		kdf.WriteBlock(0x01020304, block);
		byte[] counter = new byte[4];
		BinaryPrimitives.WriteUInt32BigEndian(counter, 0x01020304);
		kdf.Clear();
		byte[] overlapping = [.. z];
		Derive(overlapping, overlapping.AsSpan(0, 100));

		using (Assert.Multiple())
		{
			await Assert.That(key).IsEquivalentTo(expected, CollectionOrdering.Matching);
			await Assert.That(block).IsEquivalentTo(Sm3(z, counter), CollectionOrdering.Matching);
			await Assert.That(overlapping.AsSpan(0, 100).ToArray()).IsEquivalentTo(expected, CollectionOrdering.Matching);
		}
	}

	// Write, which takes lanes for several blocks, against WriteBlock one block at a time: Z of every length mod 64, a whole block before it or not, and of 703 bytes; keys of up to 72 blocks, whole or with the last cut, past two passes of the widest lanes; counters that carry into their second, third and fourth bytes within the key, and that end at the last counter.
	[Test]
	public async Task WriteMatchesSingleBlocks()
	{
		const int MaxBlocks = 72;
		uint[] counters = [1, 0xFA, 0xFFF0, 0xFF_FFE0, uint.MaxValue - MaxBlocks + 1];
		List<string> failures = [];

		foreach (int zLength in Enumerable.Range(0, 128).Append(703))
		{
			byte[] z = [.. Enumerable.Range(0, zLength).Select(static i => (byte)(i * 151 + 3))];
			SM3KdfState kdf = default;
			kdf.Initialize();
			kdf.Append(z);

			foreach (uint counter in counters)
			{
				byte[] expected = new byte[32 * MaxBlocks];

				for (int i = 0; i < MaxBlocks; ++i)
				{
					kdf.WriteBlock(counter + (uint)i, expected.AsSpan(32 * i));
				}

				for (int blocks = 1; blocks <= MaxBlocks; ++blocks)
				{
					foreach (int length in (int[])[32 * blocks - 1, 32 * blocks])
					{
						byte[] output = new byte[length + 3];
						output.AsSpan().Fill(0xA5);
						kdf.Write(counter, output.AsSpan(0, length));

						if (!output.AsSpan(0, length).SequenceEqual(expected.AsSpan(0, length)) || output.AsSpan(length).ContainsAnyExcept((byte)0xA5))
						{
							failures.Add($"Z of {zLength} bytes, counter {counter:X}, {length} bytes");
						}
					}
				}
			}

			kdf.Clear();
		}

		await Assert.That(failures).IsEmpty();
	}

	// Xor takes the key in chunks of 4096 bytes: source ⊕ the key from any counter, in place or not, and a nonzero OR of the key. IsZero finds a key of no bytes zero and those of the KDF not.
	[Test]
	public async Task XorAndIsZeroTakeTheKeyInChunks()
	{
		byte[] z = [.. Enumerable.Range(0, 100).Select(static i => (byte)(i * 29 + 1))];
		SM3KdfState kdf = default;
		kdf.Initialize();
		kdf.Append(z);
		List<string> failures = [];

		foreach (uint counter in (uint[])[1, 2, 0xFFF0])
		{
			foreach (int length in (int[])[1, 31, 32, 33, 4095, 4096, 4097, 8192, 8193, 12321])
			{
				byte[] source = [.. Enumerable.Range(0, length).Select(static i => (byte)(i * 7 + 5))];
				byte[] key = new byte[length];
				kdf.Write(counter, key);
				byte[] expected = [.. source.Zip(key, static (x, k) => (byte)(x ^ k))];
				byte[] destination = new byte[length];
				ulong accumulated = kdf.Xor(counter, source, destination);
				byte[] inPlace = [.. source];
				_ = kdf.Xor(counter, inPlace, inPlace);

				if (!destination.AsSpan().SequenceEqual(expected) || !inPlace.AsSpan().SequenceEqual(expected) || accumulated is 0 || kdf.IsZero(counter, length))
				{
					failures.Add($"counter {counter:X}, {length} bytes");
				}
			}
		}

		bool empty = kdf.IsZero(1, 0);
		kdf.Clear();

		using (Assert.Multiple())
		{
			await Assert.That(failures).IsEmpty();
			await Assert.That(empty).IsTrue();
		}
	}

	// KDF(z, destination.Length) as SM2 derives it: Z is absorbed before the key is written, so z may overlap destination.
	private static void Derive(ReadOnlySpan<byte> z, Span<byte> destination)
	{
		SM3KdfState kdf = default;

		try
		{
			kdf.Initialize();
			kdf.Append(z);
			kdf.Derive(destination);
		}
		finally
		{
			kdf.Clear();
		}
	}

	// Accumulate gives 0 for zero bytes alone, and sees a single nonzero byte at every position: in a group of vectors, a single vector, a word or the last bytes, up to a chunk of Xor and IsZero. The bytes around the span are nonzero and must not count, and the span starts at three alignments.
	[Test]
	public async Task AccumulateSeesEveryByte()
	{
		const int margin = 64;
		List<string> failures = [];

		foreach (int length in Enumerable.Range(0, 301).Append(4095).Append(4096))
		{
			foreach (int start in (int[])[margin, margin + 1, margin + 3])
			{
				byte[] buffer = new byte[start + length + margin];
				buffer.AsSpan().Fill(0xFF);
				Span<byte> bytes = buffer.AsSpan(start, length);
				bytes.Clear();

				if (FixedTime.Accumulate(bytes) is not 0)
				{
					failures.Add($"{length} zero bytes at {start}");
				}

				for (int position = 0; position < length; ++position)
				{
					bytes[position] = (byte)(1 << position % 8);

					if (FixedTime.Accumulate(bytes) is 0)
					{
						failures.Add($"{length} bytes at {start}, nonzero at {position}");
					}

					bytes[position] = 0;
				}
			}
		}

		await Assert.That(failures).IsEmpty();
	}
}
