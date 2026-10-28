using BenchmarkDotNet.Attributes;
using CryptoBase.Hashes.Sha3;
using System.Buffers.Binary;
using System.Security.Cryptography;

namespace CryptoBase.Benchmark.Hashes.Sha3;

// The SHAKE stream batches of ML-KEM and ML-DSA sampling, one KeccakSponge after another against KeccakBatchSponge groups, of streams that share a prefix and differ in a 1- or 2-byte suffix:
// 32 + 2-byte SHAKE128 seeds squeezed for three blocks each, 32 + 1-byte SHAKE256 seeds squeezed for 192 bytes each, and 64 + 2-byte SHAKE256 seeds squeezed for 576 bytes each as in ML-DSA's ExpandMask.
public class KeccakBatchSpongeBenchmark
{
	private byte[] _prefix = [];
	private byte[] _inputs = [];
	private ushort[] _suffixes = [];
	private byte[] _outputs = [];

	public static IEnumerable<ShakeBatch> Batches =>
	[
		new(128, 4, 32, 2, 3 * KeccakRate168.RateInBytes),
		new(128, 9, 32, 2, 3 * KeccakRate168.RateInBytes),
		new(128, 16, 32, 2, 3 * KeccakRate168.RateInBytes),
		new(256, 4, 32, 1, 192),
		new(128, 30, 32, 2, 3 * KeccakRate168.RateInBytes),
		new(256, 8, 64, 2, 576)
	];

	[ParamsSource(nameof(Batches))]
	public ShakeBatch Batch { get; set; }

	[GlobalSetup]
	public void Setup()
	{
		int inputLength = Batch.PrefixLength + Batch.SuffixLength;
		_prefix = RandomNumberGenerator.GetBytes(Batch.PrefixLength);
		_inputs = new byte[Batch.Streams * inputLength];
		_suffixes = new ushort[Batch.Streams];
		_outputs = new byte[Batch.Streams * Batch.OutputLength];

		for (int j = 0; j < Batch.Streams; ++j)
		{
			_suffixes[j] = (ushort)j;
			Span<byte> input = _inputs.AsSpan(j * inputLength, inputLength);
			_prefix.CopyTo(input);

			if (Batch.SuffixLength is 1)
			{
				input[Batch.PrefixLength] = (byte)j;
			}
			else
			{
				BinaryPrimitives.WriteUInt16LittleEndian(input.Slice(Batch.PrefixLength), (ushort)j);
			}
		}
	}

	[Benchmark(Baseline = true)]
	public void Sequential()
	{
		if (Batch.Shake is 128)
		{
			Sequential<KeccakRate168>();
		}
		else
		{
			Sequential<KeccakRate136>();
		}
	}

	[Benchmark]
	public void Batched()
	{
		if (Batch.Shake is 128)
		{
			Batched<KeccakRate168>();
		}
		else
		{
			Batched<KeccakRate136>();
		}
	}

	private void Sequential<TRate>() where TRate : IKeccakRate
	{
		int inputLength = Batch.PrefixLength + Batch.SuffixLength;
		int outputLength = Batch.OutputLength;

		for (int i = 0; i < Batch.Streams; ++i)
		{
			KeccakSponge<TRate> sponge = default;
			sponge.Absorb(_inputs.AsSpan(i * inputLength, inputLength));
			sponge.Pad(KeccakDomainSeparator.Shake);
			sponge.Squeeze(_outputs.AsSpan(i * outputLength, outputLength));
		}
	}

	private void Batched<TRate>() where TRate : IKeccakRate
	{
		int outputLength = Batch.OutputLength;
		KeccakBatchSponge<TRate> sponge = default;

		for (int first = 0; first < Batch.Streams; first += sponge.Count)
		{
			sponge.ResetWithGuests(Batch.Streams - first, 0, _prefix, _suffixes.AsSpan(first), Batch.SuffixLength, KeccakDomainSeparator.Shake);
			sponge.Squeeze(_outputs.AsSpan(first * outputLength, sponge.Count * outputLength));
		}
	}

	public readonly record struct ShakeBatch(int Shake, int Streams, int PrefixLength, int SuffixLength, int OutputLength)
	{
		public override string ToString()
		{
			return $"SHAKE{Shake} x{Streams} {PrefixLength}+{SuffixLength}->{OutputLength}";
		}
	}
}
