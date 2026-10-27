using CryptoBase.Abstractions.Hashes;
using CryptoBase.Hashes;
using CryptoBase.Hashes.Blake3;
using CryptoBase.Hashes.Sha3;
using System.Diagnostics.CodeAnalysis;
using static CryptoBase.Tests.TestUtils;

namespace CryptoBase.Tests.Hashes;

// Checks every IXof against its own one-shot HashData; ShakeTest, ShakeCavpTest, CShakeTest and Blake3XofTest compare that with independent oracles.
[SuppressMessage("ReSharper", "AccessToDisposedClosure")]
[GenerateGenericTest(typeof(Xof<Shake128Core>))]
[GenerateGenericTest(typeof(Xof<Shake256Core>))]
[GenerateGenericTest(typeof(Blake3HashAlgorithm))]
[GenerateGenericTest(typeof(CShake128Xof))]
[GenerateGenericTest(typeof(CShake256Xof))]
public class XofContractTest<T> where T : class, IXof<T>
{
	[Test]
	public async Task IncrementalMatchesHashData()
	{
		int block = XofContractTest.BlockLength<T>();
		int longest = 3 * block + 11;
		using T xof = T.Create();

		foreach (int inputLength in (int[])[0, 1, block - 1, block, block + 1, 3 * block + 5])
		{
			byte[] source = CreateDeterministicSource(inputLength);
			byte[] sourceCopy = (byte[])source.Clone();
			byte[] longOutput = Output(source, longest);

			foreach (int outputLength in (int[])[0, 1, block - 1, block, block + 1, longest])
			{
				byte[] expected = longOutput.AsSpan(0, outputLength).ToArray();
				await AssertWrites(expected, destination => T.HashData(source, destination));

				xof.Reset();
				xof.Append(source);
				await AssertWrites(expected, xof.GetCurrentHash);
				await AssertWrites(expected, xof.Read);

				xof.Reset();
				AppendInPieces(xof, source, inputLength + outputLength);
				await AssertWrites(expected, xof.GetHashAndReset);
			}

			await Assert.That(source).IsEquivalentTo(sourceCopy, CollectionOrdering.Matching);
		}
	}

	[Test]
	public async Task ReadInPiecesMatchesOneRead()
	{
		int block = XofContractTest.BlockLength<T>();
		int outputLength = 4 * block + 5;
		using T xof = T.Create();

		foreach (int inputLength in (int[])[0, block + 1])
		{
			byte[] source = CreateDeterministicSource(inputLength);
			byte[] expected = Output(source, outputLength);

			foreach (int[] pieceLengths in XofContractTest.PieceLengthPatterns(block))
			{
				xof.Reset();
				xof.Append(source);
				byte[] destination = new byte[outputLength + 2];
				PrepareDestination(destination);

				for (int i = 0, offset = 0; offset < outputLength; ++i)
				{
					int length = Math.Min(pieceLengths[i % pieceLengths.Length], outputLength - offset);
					xof.Read(destination.AsSpan(1 + offset, length));
					offset += length;
				}

				await AssertOutput(destination, 1, expected);
			}
		}
	}

	[Test]
	public async Task ReadingRejectsInputAndRestartsUntilReset()
	{
		int block = XofContractTest.BlockLength<T>();
		byte[] first = CreateDeterministicSource(block + 3);
		byte[] second = CreateDeterministicSource(7);
		byte[] expected = Output(Concat(first, second), 2 * block + 5);
		using T xof = T.Create();

		xof.Append(first);
		xof.Read(Span<byte>.Empty);
		xof.Append(second);

		byte[] actual = new byte[expected.Length];
		xof.Read(actual.AsSpan(0, 5));

		using (Assert.Multiple())
		{
			await Assert.That(() => xof.Append(first)).ThrowsExactly<InvalidOperationException>();
			await Assert.That(() => xof.Append(ReadOnlySpan<byte>.Empty)).ThrowsExactly<InvalidOperationException>();
			await Assert.That(() => xof.GetCurrentHash(new byte[1])).ThrowsExactly<InvalidOperationException>();
			await Assert.That(() => xof.GetCurrentHash(Span<byte>.Empty)).ThrowsExactly<InvalidOperationException>();
			await Assert.That(() => xof.GetHashAndReset(new byte[1])).ThrowsExactly<InvalidOperationException>();
		}

		// The rejected calls and an empty read leave the output stream where it was.
		xof.Read(Span<byte>.Empty);
		xof.Read(actual.AsSpan(5));
		await Assert.That(actual).IsEquivalentTo(expected, CollectionOrdering.Matching);

		xof.Reset();
		xof.Append(second);
		await AssertWrites(Output(second, block + 1), xof.GetCurrentHash);
		await AssertWrites(Output(second, block + 1), xof.Read);
	}

	[Test]
	public async Task GetCurrentHashLeavesStateUnchanged()
	{
		int block = XofContractTest.BlockLength<T>();
		byte[] first = CreateDeterministicSource(block - 1);
		byte[] second = CreateDeterministicSource(2 * block + 9);
		using T xof = T.Create();

		xof.Append(first);
		await AssertWrites(Output(first, 2 * block + 3), xof.GetCurrentHash);
		await AssertWrites(Output(first, 1), xof.GetCurrentHash);
		xof.GetCurrentHash(Span<byte>.Empty);

		xof.Append(second);
		await AssertWrites(Output(Concat(first, second), 2 * block + 3), xof.Read);
	}

	[Test]
	public async Task GetHashAndResetStartsOver()
	{
		int block = XofContractTest.BlockLength<T>();
		byte[] first = CreateDeterministicSource(block + 1);
		byte[] second = CreateDeterministicSource(3);
		using T xof = T.Create();

		xof.Append(first);
		await AssertWrites(Output(first, block + 7), xof.GetHashAndReset);
		await AssertWrites(Output([], block + 7), xof.GetCurrentHash);

		xof.Append(second);
		xof.GetHashAndReset(Span<byte>.Empty);
		await AssertWrites(Output([], 9), xof.GetCurrentHash);

		xof.Append(second);
		await AssertWrites(Output(second, block + 7), xof.Read);
	}

	[Test]
	public async Task DisposeIsIdempotentAndFinal()
	{
		T absorbing = T.Create();
		absorbing.Append([1, 2, 3]);
		T reading = T.Create();
		reading.Read(new byte[1]);

		foreach (T xof in (T[])[absorbing, reading])
		{
			xof.Dispose();
			xof.Dispose();

			using (Assert.Multiple())
			{
				await Assert.That(() => xof.Append([1])).ThrowsExactly<ObjectDisposedException>();
				await Assert.That(() => xof.Append(ReadOnlySpan<byte>.Empty)).ThrowsExactly<ObjectDisposedException>();
				await Assert.That(() => xof.Read(new byte[1])).ThrowsExactly<ObjectDisposedException>();
				await Assert.That(() => xof.Read(Span<byte>.Empty)).ThrowsExactly<ObjectDisposedException>();
				await Assert.That(() => xof.GetCurrentHash(new byte[1])).ThrowsExactly<ObjectDisposedException>();
				await Assert.That(() => xof.GetHashAndReset(new byte[1])).ThrowsExactly<ObjectDisposedException>();
				await Assert.That(xof.Reset).ThrowsExactly<ObjectDisposedException>();
			}
		}
	}

	private static byte[] Output(ReadOnlySpan<byte> source, int length)
	{
		byte[] output = new byte[length];
		T.HashData(source, output);
		return output;
	}

	private static void AppendInPieces(T xof, ReadOnlySpan<byte> source, int seed)
	{
		uint state = (uint)seed;

		while (!source.IsEmpty)
		{
			state = state * 1664525U + 1013904223U;
			int length = Math.Min((int)(state % 200U), source.Length);
			xof.Append(source.Slice(0, length));
			source = source.Slice(length);
		}
	}
}

internal static class XofContractTest
{
	internal static int BlockLength<T>()
	{
		if (typeof(T) == typeof(Xof<Shake128Core>) || typeof(T) == typeof(CShake128Xof))
		{
			return 168;
		}

		if (typeof(T) == typeof(Xof<Shake256Core>) || typeof(T) == typeof(CShake256Xof))
		{
			return 136;
		}

		return typeof(T) == typeof(Blake3HashAlgorithm) ? 64 : throw new NotSupportedException(typeof(T).Name);
	}

	// Empty reads must not advance the output, and reads may end exactly on, just before, or just after a block boundary.
	internal static IEnumerable<int[]> PieceLengthPatterns(int block)
	{
		yield return [1];
		yield return [block - 1];
		yield return [block];
		yield return [block + 1];
		yield return [2 * block + 3];
		yield return [0, 7, block - 7, 0, 2 * block, 1];
		yield return [3, 1, 4, 1, 5, 9, 2, 6, 5, 35, 89, 79, 3, 238, 46];
	}
}
