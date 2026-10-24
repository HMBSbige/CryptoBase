using CryptoBase.Kems.MLKem;
using static CryptoBase.Tests.Kems.MLKem.MLKemReference;
using static CryptoBase.Tests.TestUtils;

namespace CryptoBase.Tests.Kems.MLKem;

// Checks every kernel operation against MLKemReference, accepting any output congruent modulo q within the range IMLKemKernel states, so that the same tests hold vector kernels that reduce lazily.
public class MLKemKernelTest
{
	private static readonly int[] CompressionBits = [1, 4, 5, 10, 11];

	private static readonly int RInverse = Power(R % Q, Q - 2);

	[Test]
	public async Task EveryKernelIsListed()
	{
		await Assert.That(MLKemKernelCase.All().Select(static kernel => kernel.KernelType)).IsEquivalentTo(ImplementationsOf(typeof(IMLKemKernel)));
	}

	[Test]
	[MethodDataSource(typeof(MLKemKernelCase), nameof(MLKemKernelCase.All))]
	public async Task NttMatchesReference(MLKemKernelCase kernel)
	{
		SkipUnlessSupported(kernel);

		foreach (short[] f in Polynomials(new Random(1), Q - 1))
		{
			short[] actual = (short[])f.Clone();
			kernel.Ntt(actual);
			await AssertCongruent(actual, Ntt(ToInts(f)));
		}
	}

	[Test]
	[MethodDataSource(typeof(MLKemKernelCase), nameof(MLKemKernelCase.All))]
	public async Task InverseNttMatchesReference(MLKemKernelCase kernel)
	{
		SkipUnlessSupported(kernel);

		foreach (short[] f in Polynomials(new Random(2), Q - 1))
		{
			short[] actual = (short[])f.Clone();
			kernel.InverseNtt(actual);
			await AssertCongruent(actual, Scale(InverseNtt(ToInts(f)), R));

			// The R from NTT⁻¹ is all that remains of a round trip.
			short[] roundTrip = (short[])f.Clone();
			kernel.Ntt(roundTrip);
			kernel.InverseNtt(roundTrip);
			await AssertCongruent(roundTrip, Scale(ToInts(f), R));
		}
	}

	// Products in the NTT domain must match products of the polynomials themselves, and sums of up to four products must stay within range with every input at its largest magnitude.
	[Test]
	[MethodDataSource(typeof(MLKemKernelCase), nameof(MLKemKernelCase.All))]
	public async Task MultiplyAccumulateMatchesPolynomialProducts(MLKemKernelCase kernel)
	{
		SkipUnlessSupported(kernel);

		Random random = new(3);

		for (int count = 1; count <= 4; ++count)
		{
			foreach (int aStride in (int[])[N, count * N, 3 * N])
			{
				short[] a = new short[(count - 1) * aStride + N];
				short[] b = new short[count * N];
				int[] expected = new int[N];

				// What lies between the polynomials of a must not matter.
				for (int i = 0; i < a.Length; ++i)
				{
					a[i] = (short)random.Next(short.MinValue, short.MaxValue + 1);
				}

				for (int j = 0; j < count; ++j)
				{
					int[] f = RandomInts(random, Q);
					int[] g = RandomInts(random, Q);
					RandomRepresentatives(random, Ntt(f)).CopyTo(a, j * aStride);
					RandomRepresentatives(random, Ntt(g)).CopyTo(b, j * N);
					expected = Sum(expected, MultiplyPolynomials(f, g));
				}

				short[] actual = new short[N];
				kernel.MultiplyAccumulate(a, aStride, b, actual, count);
				await AssertCongruent(actual, Scale(Ntt(expected), RInverse));
			}

			short[] largest = Enumerable.Range(0, count * N).Select(static i => (short)(i % 3 is 0 ? -(Q - 1) : Q - 1)).ToArray();
			short[] extreme = new short[N];
			kernel.MultiplyAccumulate(largest, N, largest, extreme, count);
			int[] extremeExpected = new int[N];

			for (int j = 0; j < count; ++j)
			{
				int[] polynomial = ToInts(largest.AsSpan(j * N, N));
				extremeExpected = Sum(extremeExpected, MultiplyNtts(polynomial, polynomial));
			}

			await AssertCongruent(extreme, Scale(extremeExpected, RInverse));
		}
	}

	[Test]
	[MethodDataSource(typeof(MLKemKernelCase), nameof(MLKemKernelCase.All))]
	public async Task ReduceAndToMontgomeryCoverEveryValue(MLKemKernelCase kernel)
	{
		SkipUnlessSupported(kernel);

		for (int first = short.MinValue; first <= short.MaxValue; first += N)
		{
			short[] values = Enumerable.Range(first, N).Select(static value => (short)value).ToArray();
			short[] reduced = (short[])values.Clone();
			short[] montgomery = (short[])values.Clone();
			kernel.Reduce(reduced);
			kernel.ToMontgomery(montgomery);

			await AssertCongruent(reduced, ToInts(values));
			await AssertCongruent(montgomery, Scale(ToInts(values), R));
		}
	}

	[Test]
	[MethodDataSource(typeof(MLKemKernelCase), nameof(MLKemKernelCase.All))]
	public async Task AddAndSubtractInPlace(MLKemKernelCase kernel)
	{
		SkipUnlessSupported(kernel);

		Random random = new(4);
		short[] left = RandomPolynomial(random, 2 * Q);
		short[] right = RandomPolynomial(random, 2 * Q);
		int[] sum = ToInts(left).Zip(ToInts(right), static (x, y) => x + y).ToArray();
		int[] difference = ToInts(left).Zip(ToInts(right), static (x, y) => x - y).ToArray();

		short[] destination = new short[N];
		kernel.Add(left, right, destination);
		await Assert.That(ToInts(destination)).IsEquivalentTo(sum, CollectionOrdering.Matching);

		short[] intoLeft = (short[])left.Clone();
		kernel.Subtract(intoLeft, right, intoLeft);
		await Assert.That(ToInts(intoLeft)).IsEquivalentTo(difference, CollectionOrdering.Matching);

		short[] intoRight = (short[])right.Clone();
		kernel.Add(left, intoRight, intoRight);
		await Assert.That(ToInts(intoRight)).IsEquivalentTo(sum, CollectionOrdering.Matching);
	}

	[Test]
	[MethodDataSource(typeof(MLKemKernelCase), nameof(MLKemKernelCase.All))]
	public async Task Encode12AndDecode12MatchReference(MLKemKernelCase kernel)
	{
		SkipUnlessSupported(kernel);

		Random random = new(5);

		foreach (short[] f in Polynomials(random, Q - 1))
		{
			int[] canonical = ToInts(f).Select(static x => Mod(x)).ToArray();
			byte[] encoded = new byte[384 + 7];
			PrepareDestination(encoded);
			kernel.Encode12(f, encoded);
			await AssertOutput(encoded, ByteEncode(canonical, 12));

			short[] decoded = new short[N];
			bool valid = kernel.Decode12(encoded, decoded);

			using (Assert.Multiple())
			{
				await Assert.That(valid).IsTrue();
				await Assert.That(ToInts(decoded)).IsEquivalentTo(canonical, CollectionOrdering.Matching);
			}
		}

		// Every 12-bit value, and q and 4095 alone at either end of a pair and of the polynomial.
		for (int first = 0; first < 4096; first += N)
		{
			int[] values = Enumerable.Range(first, N).ToArray();
			await VerifyDecode12(kernel, ByteEncode(values, 12), values);
		}

		foreach (int position in (int[])[0, 1, 2, 3, 128, 129, N - 2, N - 1])
		{
			foreach (int value in (int[])[Q, 4095])
			{
				int[] values = RandomInts(random, Q).Select(static x => Mod(x)).ToArray();
				values[position] = value;
				await VerifyDecode12(kernel, ByteEncode(values, 12), values);
			}
		}
	}

	[Test]
	[MethodDataSource(typeof(MLKemKernelCase), nameof(MLKemKernelCase.All))]
	public async Task CompressMatchesFormulaForEveryValue(MLKemKernelCase kernel)
	{
		SkipUnlessSupported(kernel);

		// Every x in [0, q), then the negative representatives x − q of x in [1, q).
		int[] inputs = [.. Enumerable.Range(0, Q), .. Enumerable.Range(1 - Q, Q - 1)];

		foreach (int bits in CompressionBits)
		{
			foreach (int[] values in Chunks(inputs))
			{
				short[] f = values.Select(static x => (short)x).ToArray();
				int[] expected = values.Select(x => MLKemReference.Compress(x, bits)).ToArray();

				byte[] destination = new byte[32 * bits + 5];
				PrepareDestination(destination);
				kernel.Compress(f, destination, bits);
				await AssertOutput(destination, ByteEncode(expected, bits));
			}
		}
	}

	[Test]
	[MethodDataSource(typeof(MLKemKernelCase), nameof(MLKemKernelCase.All))]
	public async Task DecompressMatchesFormulaForEveryValue(MLKemKernelCase kernel)
	{
		SkipUnlessSupported(kernel);

		foreach (int bits in CompressionBits)
		{
			foreach (int[] values in Chunks(Enumerable.Range(0, 1 << bits).ToArray()))
			{
				short[] actual = new short[N];
				kernel.Decompress(ByteEncode(values, bits), actual, bits);
				await AssertCongruent(actual, values.Select(y => MLKemReference.Decompress(y, bits)).ToArray());
			}
		}
	}

	[Test]
	[MethodDataSource(typeof(MLKemKernelCase), nameof(MLKemKernelCase.All))]
	public async Task RejectSampleMatchesReference(MLKemKernelCase kernel)
	{
		SkipUnlessSupported(kernel);

		Random random = new(6);
		byte[] block = new byte[3 * 168];
		random.NextBytes(block);

		// Candidates of 0, q − 1, q and 4095 in both halves of a group of three bytes.
		byte[] edges = [.. Pack(Q - 1, Q - 1), .. Pack(Q, Q), .. Pack(4095, 4095), .. Pack(0, 4095), .. Pack(4095, 0), .. Pack(Q - 1, Q), .. Pack(Q, Q - 1)];

		foreach (byte[] source in (byte[][])[block, block.AsSpan(0, 168).ToArray(), edges, new byte[3 * 168], Enumerable.Repeat((byte)0xFF, 3 * 168).ToArray()])
		{
			foreach (int capacity in (int[])[N, N - 1, 1, 7, 0])
			{
				List<int> expected = MLKemReference.RejectSample(source, capacity);
				short[] destination = new short[capacity + 3];
				destination.AsSpan().Fill(-1);
				int count = kernel.RejectSample(source, destination.AsSpan(0, capacity));

				using (Assert.Multiple())
				{
					await Assert.That(count).IsEqualTo(expected.Count);
					await Assert.That(ToInts(destination.AsSpan(0, expected.Count))).IsEquivalentTo(expected, CollectionOrdering.Matching);
					await Assert.That(destination.AsSpan(expected.Count).ToArray()).All(static value => value is -1);
				}
			}
		}
	}

	[Test]
	[MethodDataSource(typeof(MLKemKernelCase), nameof(MLKemKernelCase.All))]
	public async Task SampleCbdMatchesReference(MLKemKernelCase kernel)
	{
		SkipUnlessSupported(kernel);

		Random random = new(7);

		foreach (int eta in (int[])[2, 3])
		{
			byte[] randomBytes = new byte[64 * eta];
			random.NextBytes(randomBytes);

			foreach (byte[] source in (byte[][])[randomBytes, new byte[64 * eta], Enumerable.Repeat((byte)0xFF, 64 * eta).ToArray(), Enumerable.Repeat((byte)0x0F, 64 * eta).ToArray()])
			{
				short[] actual = new short[N];
				kernel.SampleCbd(source, actual, eta);
				await Assert.That(ToInts(actual)).IsEquivalentTo(SamplePolyCbd(source, eta), CollectionOrdering.Matching);
			}
		}
	}

	// Vector kernels load and store whole registers, so inputs and outputs may end at an inaccessible page.
	[Test]
	[MethodDataSource(typeof(MLKemKernelCase), nameof(MLKemKernelCase.All))]
	public async Task StaysWithinBuffers(MLKemKernelCase kernel)
	{
		SkipUnlessSupported(kernel);

		GuardPageBuffer.SkipUnlessSupported();

		Random random = new(8);
		short[] f = RandomPolynomial(random, Q - 1);
		int[] canonical = ToInts(f).Select(static x => Mod(x)).ToArray();

		using (GuardPageBuffer encoded = new(384))
		{
			kernel.Encode12(f, encoded.Span);
			await Assert.That(encoded.Span.ToArray()).IsEquivalentTo(ByteEncode(canonical, 12), CollectionOrdering.Matching);
			await Assert.That(kernel.Decode12(encoded.Span, new short[N])).IsTrue();
		}

		foreach (int bits in CompressionBits)
		{
			using GuardPageBuffer compressed = new(32 * bits);
			kernel.Compress(f, compressed.Span, bits);
			await Assert.That(compressed.Span.ToArray()).IsEquivalentTo(ByteEncode(canonical.Select(x => MLKemReference.Compress(x, bits)).ToArray(), bits), CollectionOrdering.Matching);
			kernel.Decompress(compressed.Span, new short[N], bits);
		}

		foreach (int length in (int[])[168, 3 * 168, 3])
		{
			using GuardPageBuffer source = new(length);
			random.NextBytes(source.Span);
			short[] destination = new short[N];
			await Assert.That(kernel.RejectSample(source.Span, destination)).IsEqualTo(MLKemReference.RejectSample(source.Span, N).Count);
		}

		foreach (int eta in (int[])[2, 3])
		{
			using GuardPageBuffer source = new(64 * eta);
			random.NextBytes(source.Span);
			short[] actual = new short[N];
			kernel.SampleCbd(source.Span, actual, eta);
			await Assert.That(ToInts(actual)).IsEquivalentTo(SamplePolyCbd(source.Span, eta), CollectionOrdering.Matching);
		}
	}

	private static void SkipUnlessSupported(MLKemKernelCase kernel)
	{
		if (!kernel.IsSupported)
		{
			Skip.Test($"{kernel} is not supported here.");
		}
	}

	private static async Task VerifyDecode12(MLKemKernelCase kernel, byte[] source, int[] values)
	{
		short[] decoded = new short[N];
		bool valid = kernel.Decode12(source, decoded);

		using (Assert.Multiple())
		{
			await Assert.That(valid).IsEqualTo(values.All(static value => value < Q));
			await Assert.That(ToInts(decoded)).IsEquivalentTo(values, CollectionOrdering.Matching);
		}
	}

	// A kernel output must be congruent to the expected value and below q in magnitude.
	private static async Task AssertCongruent(short[] actual, int[] expected)
	{
		List<string> mismatches = [];

		for (int i = 0; i < expected.Length; ++i)
		{
			if (Math.Abs((int)actual[i]) >= Q || Mod(actual[i]) != Mod(expected[i]))
			{
				mismatches.Add($"[{i}] = {actual[i]}, expected {Mod(expected[i])} mod q");
			}
		}

		await Assert.That(mismatches).IsEmpty();
	}

	// Random polynomials with coefficients at most bound in magnitude, then ones at the bound and zero.
	private static IEnumerable<short[]> Polynomials(Random random, int bound)
	{
		for (int i = 0; i < 6; ++i)
		{
			yield return RandomPolynomial(random, bound);
		}

		yield return Enumerable.Repeat((short)bound, N).ToArray();
		yield return Enumerable.Repeat((short)-bound, N).ToArray();
		yield return Enumerable.Range(0, N).Select(i => (short)(i % 2 is 0 ? bound : -bound)).ToArray();
		yield return new short[N];
	}

	// Splits values into polynomials, padding the last with zeros.
	private static IEnumerable<int[]> Chunks(int[] values)
	{
		for (int first = 0; first < values.Length; first += N)
		{
			int[] chunk = new int[N];
			values.AsSpan(first, Math.Min(N, values.Length - first)).CopyTo(chunk);
			yield return chunk;
		}
	}

	// Two 12-bit SampleNTT candidates as the three bytes they come from.
	private static byte[] Pack(int first, int second)
	{
		return [(byte)first, (byte)(first >> 8 | second << 4), (byte)(second >> 4)];
	}

	private static short[] RandomPolynomial(Random random, int bound)
	{
		return RandomInts(random, bound + 1).Select(static x => (short)x).ToArray();
	}

	// Values in (−bound, bound).
	private static int[] RandomInts(Random random, int bound)
	{
		return Enumerable.Range(0, N).Select(_ => random.Next(1 - bound, bound)).ToArray();
	}

	// x or x − q for each x in [0, q), so that inputs cover the whole range a kernel accepts.
	private static short[] RandomRepresentatives(Random random, int[] values)
	{
		return values.Select(x => (short)(random.Next(2) is 0 ? x : x - Q)).ToArray();
	}

	private static int[] ToInts(ReadOnlySpan<short> values)
	{
		int[] result = new int[values.Length];

		for (int i = 0; i < values.Length; ++i)
		{
			result[i] = values[i];
		}

		return result;
	}

	private static int[] Scale(int[] values, int factor)
	{
		return values.Select(x => Mod((long)x * factor)).ToArray();
	}

	private static int[] Sum(int[] left, int[] right)
	{
		return left.Zip(right, static (x, y) => Mod(x + y)).ToArray();
	}
}
