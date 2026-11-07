using CryptoBase.Hashes;
using CryptoBase.Hashes.SM3;
using System.Buffers.Binary;
using static CryptoBase.Tests.TestUtils;

namespace CryptoBase.Tests.Hashes.SM3;

public class SM3LanesTest
{
	// Around the carries of the counter bytes; each test adds the counter whose key ends at the last counter.
	private static readonly uint[] Counters = [1, 0xF5, 0xFFF3, 0xFF_FFF1, 0x01FF_FFEF];

	private static readonly uint[] ExtremeWords = [0, uint.MaxValue, 0x8000_0000, 0x7FFF_FFFF, 0xAAAA_AAAA, 0x5555_5555, 1];

	[Test]
	public async Task EveryKernelIsListed()
	{
		Type[] kernels = [.. typeof(ISM3Lanes<>).Assembly.GetTypes().Where(static type => !type.IsInterface && type.GetInterfaces().Any(static face => face.IsGenericType && face.GetGenericTypeDefinition() == typeof(ISM3Lanes<>)))];

		await Assert.That(SM3LanesCase.All().Select(static kernel => kernel.KernelType)).IsEquivalentTo(kernels);
	}

	// The reference that the kernels are checked against hashes as SM3Core does, around the padding of one and two blocks.
	[Test]
	public async Task ReferenceMatchesSM3Core()
	{
		List<int> failures = [];

		for (int length = 0; length <= 200; ++length)
		{
			byte[] message = CreateDeterministicSource(length);

			if (!Sm3(message).AsSpan().SequenceEqual(SM3Reference.Hash(message)))
			{
				failures.Add(length);
			}
		}

		await Assert.That(failures).IsEmpty();
	}

	// Every lane compresses a state and a block of its own, random or of extreme words, as the reference does.
	[Test]
	[MethodDataSource(typeof(SM3LanesCase), nameof(SM3LanesCase.All))]
	public async Task CompressMatchesReference(SM3LanesCase kernel)
	{
		SkipUnlessSupported(kernel);

		Random random = new(kernel.LaneCount);
		List<string> failures = [];

		for (int trial = 0; trial < 64; ++trial)
		{
			Lanes group = new(kernel.LaneCount, trial, random);
			kernel.Compress(group.State, group.Block);
			group.Check($"trial {trial}", failures);
		}

		await Assert.That(failures).IsEmpty();
	}

	// Compress of two groups, each with lanes of its own, as the reference does.
	[Test]
	[MethodDataSource(typeof(SM3LanesCase), nameof(SM3LanesCase.All))]
	public async Task CompressPairMatchesReference(SM3LanesCase kernel)
	{
		SkipUnlessSupported(kernel);

		Random random = new(2 * kernel.LaneCount);
		List<string> failures = [];

		for (int trial = 0; trial < 64; ++trial)
		{
			Lanes group0 = new(kernel.LaneCount, trial, random);
			Lanes group1 = new(kernel.LaneCount, trial + 1, random);
			kernel.Compress(group0.State, group0.Block, group1.State, group1.Block);
			group0.Check($"trial {trial}, group 0", failures);
			group1.Check($"trial {trial}, group 1", failures);
		}

		await Assert.That(failures).IsEmpty();
	}

	// SM3(prefix ‖ ct) for each counter, for a prefix of every length mod 64, whole blocks before it or not, and keys of a block or part of one up to more than four groups of lanes: passes of two groups, or of one where Write takes them one at a time, then the rest.
	[Test]
	[MethodDataSource(typeof(SM3LanesCase), nameof(SM3LanesCase.All))]
	public async Task WriteMatchesSingleBlocks(SM3LanesCase kernel)
	{
		SkipUnlessSupported(kernel);

		int lanes = kernel.LaneCount;
		int maxBlocks = 4 * lanes + 2;
		int groupLength = 32 * lanes;
		int[] lengths = [.. new[] { 1, 31, 32, 33 }.Concat(Enumerable.Range(1, 4).SelectMany(groups => new[] { -33, -32, -1, 0, 1, 32, 33 }.Select(offset => groups * groupLength + offset))).Append(32 * maxBlocks).Where(static length => length > 0).Distinct()];
		List<string> failures = [];

		foreach (int prefixLength in Enumerable.Range(0, 128).Append(703))
		{
			byte[] prefix = CreateDeterministicSource(prefixLength);
			SM3Core core = HashCore.Create<SM3Core>();
			HashCore.Append(ref core, prefix);

			foreach (uint counter in Counters.Append(uint.MaxValue - (uint)maxBlocks + 1))
			{
				byte[] expected = new byte[32 * maxBlocks];

				for (int i = 0; i < maxBlocks; ++i)
				{
					byte[] encodedCounter = new byte[4];
					BinaryPrimitives.WriteUInt32BigEndian(encodedCounter, counter + (uint)i);
					Sm3([.. prefix, .. encodedCounter]).CopyTo(expected, 32 * i);
				}

				foreach (int length in lengths)
				{
					byte[] output = new byte[length + 5];
					PrepareDestination(output);
					kernel.Write(in core, counter, output.AsSpan(0, length));

					if (!output.AsSpan(0, length).SequenceEqual(expected.AsSpan(0, length)) || output.AsSpan(length).ContainsAnyExcept(DestinationSentinel))
					{
						failures.Add($"prefix of {prefixLength} bytes, counter {counter:X}, {length} bytes");
					}
				}
			}
		}

		await Assert.That(failures).IsEmpty();
	}

	private static byte[] Sm3(byte[] message)
	{
		byte[] hash = new byte[32];
		_ = HashAlgorithm<SM3Core>.HashData(message, hash);
		return hash;
	}

	// The states and blocks of a group of lanes, word-major as the kernels take them, and those of each lane for the reference.
	private sealed class Lanes
	{
		private readonly int _count;
		private readonly uint[][] _laneStates;
		private readonly uint[][] _laneBlocks;

		public Lanes(int count, int trial, Random random)
		{
			_count = count;
			_laneStates = new uint[count][];
			_laneBlocks = new uint[count][];
			State = new uint[8 * count];
			Block = new uint[16 * count];

			for (int lane = 0; lane < count; ++lane)
			{
				// The kind of input varies with the lane as well as the trial, so that neighbouring lanes differ.
				int kind = (trial + 3 * lane) % 4;
				_laneStates[lane] = Words(8, (kind & 1) is not 0, trial + lane, random);
				_laneBlocks[lane] = Words(16, (kind & 2) is not 0, 2 * trial + lane, random);

				for (int j = 0; j < 8; ++j)
				{
					State[j * count + lane] = _laneStates[lane][j];
				}

				for (int j = 0; j < 16; ++j)
				{
					Block[j * count + lane] = _laneBlocks[lane][j];
				}
			}
		}

		public uint[] State { get; }

		public uint[] Block { get; }

		public void Check(string name, List<string> failures)
		{
			for (int lane = 0; lane < _count; ++lane)
			{
				uint[] expected = [.. _laneStates[lane]];
				SM3Reference.Compress(expected, _laneBlocks[lane]);

				for (int j = 0; j < 8; ++j)
				{
					if (State[j * _count + lane] != expected[j])
					{
						failures.Add($"{name}, lane {lane}, word {j}");
					}
				}
			}
		}

		private static uint[] Words(int count, bool extreme, int seed, Random random)
		{
			uint[] words = new uint[count];

			for (int i = 0; i < count; ++i)
			{
				words[i] = extreme ? ExtremeWords[(seed + i * (seed % 3 + 1)) % ExtremeWords.Length] : (uint)random.NextInt64(1L << 32);
			}

			return words;
		}
	}
}
