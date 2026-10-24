using BenchmarkDotNet.Attributes;
using CryptoBase.Hashes.Sha3;
using System.Security.Cryptography;

namespace CryptoBase.Benchmark.Hashes.Sha3;

// The SHAKE stream batches of ML-KEM and ML-DSA sampling, one KeccakSponge after another against KeccakBatchSponge groups:
// 34-byte SHAKE128 seeds squeezed for three blocks each, 33-byte SHAKE256 seeds squeezed for 192 bytes each, and 66-byte SHAKE256 seeds squeezed for 576 bytes each as in ML-DSA's ExpandMask. The 96- and 128-byte SHAKE256 inputs squeezed for 32 bytes are the F, PRF and H calls of SLH-DSA with n = 32, one permutation per stream.
public class KeccakBatchSpongeBenchmark
{
	private byte[] _inputs = [];
	private byte[] _outputs = [];

	public static IEnumerable<ShakeBatch> Batches =>
	[
		new(128, 4, 34, 3 * KeccakRate168.RateInBytes),
		new(128, 9, 34, 3 * KeccakRate168.RateInBytes),
		new(128, 16, 34, 3 * KeccakRate168.RateInBytes),
		new(256, 4, 33, 192),
		new(128, 30, 34, 3 * KeccakRate168.RateInBytes),
		new(256, 8, 66, 576),
		new(256, 8, 96, 32),
		new(256, 8, 128, 32)
	];

	[ParamsSource(nameof(Batches))]
	public ShakeBatch Batch { get; set; }

	[GlobalSetup]
	public void Setup()
	{
		_inputs = RandomNumberGenerator.GetBytes(Batch.Streams * Batch.InputLength);
		_outputs = new byte[Batch.Streams * Batch.OutputLength];
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
		int inputLength = Batch.InputLength;
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
		int inputLength = Batch.InputLength;
		int outputLength = Batch.OutputLength;
		KeccakBatchSponge<TRate> sponge = default;

		for (int first = 0; first < Batch.Streams; first += sponge.Count)
		{
			sponge.ResetWithGuests(Batch.Streams - first, 0);
			sponge.Absorb(_inputs.AsSpan(first * inputLength, sponge.Count * inputLength));
			sponge.Pad(KeccakDomainSeparator.Shake);
			sponge.Squeeze(_outputs.AsSpan(first * outputLength, sponge.Count * outputLength));
		}
	}

	public readonly record struct ShakeBatch(int Shake, int Streams, int InputLength, int OutputLength)
	{
		public override string ToString()
		{
			return $"SHAKE{Shake} x{Streams} {InputLength}->{OutputLength}";
		}
	}
}
