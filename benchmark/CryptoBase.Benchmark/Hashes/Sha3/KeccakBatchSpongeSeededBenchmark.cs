using BenchmarkDotNet.Attributes;
using CryptoBase.Hashes.Sha3;
using System.Buffers.Binary;
using System.Security.Cryptography;

namespace CryptoBase.Benchmark.Hashes.Sha3;

// Compares two ways to prepare a batch, up to its first permutation, of streams that share a prefix and differ in a 1- or 2-byte suffix: absorbing whole inputs from a buffer, and writing them straight into the state with the seeded Reset.
// The batches are those of ExpandA of ML-DSA and ML-KEM with a 32-byte ρ, the PRF of ML-KEM with a 32-byte σ, and ExpandS and ExpandMask of ML-DSA with a 64-byte ρ′ or ρ″.
public class KeccakBatchSpongeSeededBenchmark
{
	private const int MaxStreams = 8;

	private byte[] _prefix = [];
	private byte[] _inputs = [];
	private ushort[] _suffixes = [];

	// Fields rather than locals, so that the state written is observable and not discarded.
	private KeccakBatchSponge<KeccakRate168> _shake128;
	private KeccakBatchSponge<KeccakRate136> _shake256;

	public static IEnumerable<SeededBatch> Batches =>
	[
		new(128, 4, 32, 2),
		new(256, 4, 32, 1),
		new(256, 7, 64, 2),
		new(256, 8, 64, 2)
	];

	[ParamsSource(nameof(Batches))]
	public SeededBatch Batch { get; set; }

	[GlobalSetup]
	public void Setup()
	{
		int inputLength = Batch.PrefixLength + Batch.SuffixLength;
		_prefix = RandomNumberGenerator.GetBytes(Batch.PrefixLength);
		_inputs = new byte[MaxStreams * inputLength];
		_suffixes = new ushort[MaxStreams];

		for (int j = 0; j < MaxStreams; ++j)
		{
			_prefix.CopyTo(_inputs, j * inputLength);
		}
	}

	[Benchmark(Baseline = true)]
	public void Absorbed()
	{
		if (Batch.Shake is 128)
		{
			Absorbed(ref _shake128);
		}
		else
		{
			Absorbed(ref _shake256);
		}
	}

	[Benchmark]
	public void Seeded()
	{
		if (Batch.Shake is 128)
		{
			Seeded(ref _shake128);
		}
		else
		{
			Seeded(ref _shake256);
		}
	}

	private void Absorbed<TRate>(ref KeccakBatchSponge<TRate> sponge) where TRate : IKeccakRate
	{
		int prefixLength = Batch.PrefixLength;
		int inputLength = prefixLength + Batch.SuffixLength;
		sponge.ResetWithGuests(Batch.Streams, 0);
		int count = sponge.Count;
		Span<byte> inputs = _inputs.AsSpan(0, count * inputLength);

		for (int j = 0; j < count; ++j)
		{
			if (Batch.SuffixLength is 1)
			{
				inputs[j * inputLength + prefixLength] = (byte)j;
			}
			else
			{
				BinaryPrimitives.WriteUInt16LittleEndian(inputs.Slice(j * inputLength + prefixLength), (ushort)j);
			}
		}

		sponge.Absorb(inputs);
		sponge.Pad(KeccakDomainSeparator.Shake);
	}

	private void Seeded<TRate>(ref KeccakBatchSponge<TRate> sponge) where TRate : IKeccakRate
	{
		int group = Math.Min(Batch.Streams, MaxStreams);
		Span<ushort> suffixes = _suffixes.AsSpan(0, group);

		for (int j = 0; j < group; ++j)
		{
			suffixes[j] = (ushort)j;
		}

		sponge.ResetWithGuests(Batch.Streams, 0, _prefix, suffixes, Batch.SuffixLength, KeccakDomainSeparator.Shake);
	}

	public readonly record struct SeededBatch(int Shake, int Streams, int PrefixLength, int SuffixLength)
	{
		public override string ToString()
		{
			return $"SHAKE{Shake} x{Streams} {PrefixLength}+{SuffixLength}";
		}
	}
}
