using BenchmarkDotNet.Attributes;
using CryptoBase.Hashes.Blake3;
using System.Security.Cryptography;

namespace CryptoBase.Benchmark.Hashes.Blake3;

// ReadDistance spans both sides of Blake3HashAlgorithm's chunk mode interval for every SIMD kernel, so both chunk mode and group mode are measured.
public class Blake3HashAlgorithmBenchmark
{
	private const int InputLength = 64 * 1024;

	private readonly byte[] _input = RandomNumberGenerator.GetBytes(InputLength);
	private readonly byte[] _hash = new byte[Blake3HashAlgorithm.HashLength];
	private readonly Blake3HashAlgorithm _hasher = Blake3HashAlgorithm.Create();

	[Params(64, 1000)] public int PieceLength { get; set; }

	[Params(0, 64, 1024, 2048, 4096, 8192)]
	public int ReadDistance { get; set; }

	[GlobalCleanup]
	public void Cleanup()
	{
		_hasher.Dispose();
	}

	[Benchmark]
	public void AppendAndRead()
	{
		int pieceLength = PieceLength;
		int readDistance = ReadDistance;
		int unread = 0;
		_hasher.Reset();

		for (int offset = 0; offset < InputLength; offset += pieceLength)
		{
			int length = Math.Min(pieceLength, InputLength - offset);
			_hasher.Append(_input.AsSpan(offset, length));
			unread += length;

			if (readDistance is not 0 && unread >= readDistance)
			{
				_hasher.GetCurrentHash(_hash);
				unread = 0;
			}
		}

		_hasher.GetCurrentHash(_hash);
	}
}
