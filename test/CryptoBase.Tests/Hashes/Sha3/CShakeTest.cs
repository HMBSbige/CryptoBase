using CryptoBase.Abstractions.Hashes;
using CryptoBase.Hashes;
using CryptoBase.Hashes.Sha3;
using System.Diagnostics.CodeAnalysis;
using System.Text;
using static CryptoBase.Tests.TestUtils;

namespace CryptoBase.Tests.Hashes.Sha3;

// XofContractTest covers the IXof contract of Create(), which is SHAKE; these tests cover a function name and customization string, which
// every operation must keep, and the equivalence with SHAKE when both are empty.
public class CShakeTest
{
	private static readonly byte[] Name = "KMAC"u8.ToArray();
	private static readonly byte[] Customization = "My Tagged Application"u8.ToArray();

	[Test]
	[MethodDataSource(typeof(Sp800_185Samples), nameof(Sp800_185Samples.CShake))]
	public async Task MatchesNistSamples(CShakeSample sample)
	{
		byte[] expected = Convert.FromHexString(sample.Output);
		byte[] customization = Encoding.ASCII.GetBytes(sample.Customization);

		if (sample.SecurityStrength is 128)
		{
			await VerifySample<CShake128Xof>(sample.Data, customization, expected);
		}
		else
		{
			await VerifySample<CShake256Xof>(sample.Data, customization, expected);
		}
	}

	// SP 800-185, Sec. 3.3: with an empty function name and customization string, cSHAKE is SHAKE.
	[Test]
	[GenerateGenericTest(typeof(CShake128Xof), typeof(Shake128HashAlgorithm))]
	[GenerateGenericTest(typeof(CShake256Xof), typeof(Shake256HashAlgorithm))]
	public async Task EmptyNameAndCustomizationGiveShake<T, TShake>() where T : class, IXof<T> where TShake : unmanaged, IXofCore<TShake>
	{
		int rate = Rate<T>();

		foreach (int inputLength in (int[])[0, 1, rate - 1, rate, rate + 1, 3 * rate + 5])
		{
			byte[] source = CreateDeterministicSource(inputLength);
			byte[] expected = new byte[2 * rate + 3];
			Xof<TShake>.HashData(source, expected);

			using T created = T.Create();
			created.Append(source);
			using T customized = Create<T>([], []);
			customized.Append(source);

			using (Assert.Multiple())
			{
				await AssertWrites(expected, destination => T.HashData(source, destination));
				await AssertWrites(expected, destination => HashData<T>([], [], source, destination));
				await AssertWrites(expected, created.Read);
				await AssertWrites(expected, customized.Read);
			}
		}
	}

	// The prefix takes one block for short strings, and two for the pair of rate and rate - 8 bytes: 2 + (3 + rate) + (3 + rate - 8) bytes end on
	// the boundary. The lengths of the last pair, 65536 bits and more, take three bytes to encode.
	[Test]
	[GenerateGenericTest(typeof(CShake128Xof))]
	[GenerateGenericTest(typeof(CShake256Xof))]
	public async Task MatchesReference<T>() where T : class, IXof<T>
	{
		int rate = Rate<T>();
		int outputLength = 2 * rate + 3;
		(byte[] Name, byte[] Customization)[] pairs =
		[
			(Name, []),
			([], Customization),
			(Name, Customization),
			(CreateDeterministicSource(rate), CreateDeterministicSource(rate - 8)),
			(CreateDeterministicSource(8192), CreateDeterministicSource(8200))
		];

		foreach ((byte[] name, byte[] customization) in pairs)
		{
			foreach (int inputLength in (int[])[0, 1, rate - 1, rate, rate + 1, 3 * rate + 5])
			{
				byte[] source = CreateDeterministicSource(inputLength);
				byte[] expected = KeccakReference.CShake(source, rate, name, customization, outputLength);
				using T xof = Create<T>(name, customization);
				xof.Append(source);

				using (Assert.Multiple())
				{
					await AssertWrites(expected, destination => HashData<T>(name, customization, source, destination));
					await AssertWrites(expected, xof.GetCurrentHash);
					await AssertWrites(expected, xof.Read);
				}
			}
		}
	}

	[Test]
	[GenerateGenericTest(typeof(CShake128Xof))]
	[GenerateGenericTest(typeof(CShake256Xof))]
	public async Task AppendInPiecesMatchesOneAppend<T>() where T : class, IXof<T>
	{
		int rate = Rate<T>();
		byte[] source = CreateDeterministicSource(7 * rate + 13);
		byte[] expected = Output<T>(source, 3 * rate + 11);
		using T xof = Create<T>(Name, Customization);

		foreach (int[] pieceLengths in XofContractTest.PieceLengthPatterns(rate))
		{
			for (int i = 0, offset = 0; offset < source.Length; ++i)
			{
				int length = Math.Min(pieceLengths[i % pieceLengths.Length], source.Length - offset);
				xof.Append(source.AsSpan(offset, length));
				offset += length;
			}

			await AssertWrites(expected, xof.GetHashAndReset);
		}
	}

	[Test]
	[GenerateGenericTest(typeof(CShake128Xof))]
	[GenerateGenericTest(typeof(CShake256Xof))]
	public async Task ReadInPiecesMatchesOneRead<T>() where T : class, IXof<T>
	{
		int rate = Rate<T>();
		byte[] source = CreateDeterministicSource(rate + 1);
		int outputLength = 4 * rate + 5;
		byte[] expected = Output<T>(source, outputLength);
		using T xof = Create<T>(Name, Customization);

		foreach (int[] pieceLengths in XofContractTest.PieceLengthPatterns(rate))
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

	[Test]
	[GenerateGenericTest(typeof(CShake128Xof))]
	[GenerateGenericTest(typeof(CShake256Xof))]
	public async Task GetCurrentHashLeavesStateUnchanged<T>() where T : class, IXof<T>
	{
		int rate = Rate<T>();
		byte[] first = CreateDeterministicSource(rate - 1);
		byte[] second = CreateDeterministicSource(2 * rate + 9);
		using T xof = Create<T>(Name, Customization);

		xof.Append(first);
		await AssertWrites(Output<T>(first, 2 * rate + 3), xof.GetCurrentHash);
		await AssertWrites(Output<T>(first, 1), xof.GetCurrentHash);
		xof.GetCurrentHash(Span<byte>.Empty);

		xof.Append(second);
		await AssertWrites(Output<T>(Concat(first, second), 2 * rate + 3), xof.Read);
	}

	[Test]
	[GenerateGenericTest(typeof(CShake128Xof))]
	[GenerateGenericTest(typeof(CShake256Xof))]
	public async Task ResetsKeepNameAndCustomization<T>() where T : class, IXof<T>
	{
		int rate = Rate<T>();
		byte[] first = CreateDeterministicSource(rate + 1);
		byte[] second = CreateDeterministicSource(3);
		using T xof = Create<T>(Name, Customization);

		xof.Append(first);
		await AssertWrites(Output<T>(first, rate + 7), xof.GetHashAndReset);
		await AssertWrites(Output<T>([], rate + 7), xof.GetCurrentHash);

		xof.Append(second);
		await AssertWrites(Output<T>(second, rate + 7), xof.Read);

		xof.Reset();
		await AssertWrites(Output<T>([], 9), xof.GetCurrentHash);
		xof.Append(first);
		await AssertWrites(Output<T>(first, rate + 7), xof.Read);
	}

	[Test]
	[GenerateGenericTest(typeof(CShake128Xof))]
	[GenerateGenericTest(typeof(CShake256Xof))]
	[SuppressMessage("ReSharper", "AccessToDisposedClosure", Justification = "Assertions are awaited before the instance is disposed.")]
	public async Task ReadingRejectsInputUntilReset<T>() where T : class, IXof<T>
	{
		int rate = Rate<T>();
		byte[] first = CreateDeterministicSource(rate + 3);
		byte[] second = CreateDeterministicSource(7);
		byte[] expected = Output<T>(Concat(first, second), 2 * rate + 5);
		using T xof = Create<T>(Name, Customization);

		// An empty read leaves the input open.
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
			await Assert.That(() => xof.GetHashAndReset(new byte[1])).ThrowsExactly<InvalidOperationException>();
		}

		xof.Read(Span<byte>.Empty);
		xof.Read(actual.AsSpan(5));
		await Assert.That(actual).IsEquivalentTo(expected, CollectionOrdering.Matching);

		xof.Reset();
		xof.Append(second);
		await AssertWrites(Output<T>(second, rate + 1), xof.Read);
	}

	[Test]
	[GenerateGenericTest(typeof(CShake128Xof))]
	[GenerateGenericTest(typeof(CShake256Xof))]
	[SuppressMessage("ReSharper", "AccessToDisposedClosure", Justification = "Assertions are awaited before reading is disposed.")]
	public async Task CloneIsIndependent<T>() where T : class, IXof<T>
	{
		int rate = Rate<T>();
		byte[] source = CreateDeterministicSource(rate + 32);
		byte[] expected = Output<T>(Concat(source, source), 3 * rate);
		using T xof = Create<T>(Name, Customization);
		xof.Append(source);

		using T absorbing = Clone(xof);
		absorbing.Append(source);
		await AssertWrites(expected, absorbing.GetCurrentHash);
		await AssertWrites(Output<T>(source, 3 * rate), xof.GetCurrentHash);

		xof.Append(source);
		byte[] actual = new byte[expected.Length];
		xof.Read(actual.AsSpan(0, rate + 2));
		T reading = Clone(xof);
		byte[] rest = new byte[expected.Length - (rate + 2)];
		xof.Read(rest);
		reading.Read(actual.AsSpan(rate + 2));

		using (Assert.Multiple())
		{
			await Assert.That(actual).IsEquivalentTo(expected, CollectionOrdering.Matching);
			await Assert.That(rest).IsEquivalentTo(expected.AsSpan(rate + 2).ToArray(), CollectionOrdering.Matching);
			await Assert.That(() => reading.Append(source)).ThrowsExactly<InvalidOperationException>();
		}

		// The clone keeps the function name and customization string through a reset.
		reading.Reset();
		reading.Append(source);
		await AssertWrites(Output<T>(source, rate + 1), reading.Read);

		reading.Dispose();
		await Assert.That(() => Clone(reading)).ThrowsExactly<ObjectDisposedException>();
	}

	[Test]
	[GenerateGenericTest(typeof(CShake128Xof))]
	[GenerateGenericTest(typeof(CShake256Xof))]
	public async Task DisposeIsIdempotentAndFinal<T>() where T : class, IXof<T>
	{
		T absorbing = Create<T>(Name, Customization);
		absorbing.Append([1, 2, 3]);
		T reading = Create<T>(Name, Customization);
		reading.Read(new byte[1]);

		foreach (T xof in (T[])[absorbing, reading])
		{
			xof.Dispose();
			xof.Dispose();

			using (Assert.Multiple())
			{
				await Assert.That(() => xof.Append([1])).ThrowsExactly<ObjectDisposedException>();
				await Assert.That(() => xof.Read(new byte[1])).ThrowsExactly<ObjectDisposedException>();
				await Assert.That(() => xof.Read(Span<byte>.Empty)).ThrowsExactly<ObjectDisposedException>();
				await Assert.That(() => xof.GetCurrentHash(new byte[1])).ThrowsExactly<ObjectDisposedException>();
				await Assert.That(() => xof.GetHashAndReset(new byte[1])).ThrowsExactly<ObjectDisposedException>();
				await Assert.That(xof.Reset).ThrowsExactly<ObjectDisposedException>();
				await Assert.That(() => Clone(xof)).ThrowsExactly<ObjectDisposedException>();
			}
		}
	}

	// The prefix is absorbed before the output is written, so the destination may overlap the source.
	[Test]
	[GenerateGenericTest(typeof(CShake128Xof))]
	[GenerateGenericTest(typeof(CShake256Xof))]
	public async Task HashDataSupportsOverlappingSourceAndDestination<T>() where T : class, IXof<T>
	{
		int rate = Rate<T>();
		byte[] source = CreateDeterministicSource(rate + 9);
		byte[] expected = Output<T>(source, 2 * rate + 1);

		await HashAlgorithmTestUtils.VerifyOverlappingHashData(source, expected, (input, output) =>
		{
			HashData<T>(Name, Customization, input, output.Slice(0, expected.Length));
			return expected.Length;
		});
	}

	private delegate void OutputWriter(Span<byte> destination);

	private static async Task VerifySample<T>(byte[] data, byte[] customization, byte[] expected) where T : class, IXof<T>
	{
		using T xof = Create<T>([], customization);
		xof.Append(data);

		using (Assert.Multiple())
		{
			await AssertWrites(expected, destination => HashData<T>([], customization, data, destination));
			await AssertWrites(expected, xof.Read);
		}
	}

	private static int Rate<T>()
	{
		return typeof(T) == typeof(CShake128Xof) ? 168 : typeof(T) == typeof(CShake256Xof) ? 136 : throw new NotSupportedException(typeof(T).Name);
	}

	private static T Create<T>(ReadOnlySpan<byte> functionName, ReadOnlySpan<byte> customization) where T : class, IXof<T>
	{
		if (typeof(T) == typeof(CShake128Xof))
		{
			return (T)(object)CShake128Xof.Create(functionName, customization);
		}

		return typeof(T) == typeof(CShake256Xof) ? (T)(object)CShake256Xof.Create(functionName, customization) : throw new NotSupportedException(typeof(T).Name);
	}

	private static void HashData<T>(ReadOnlySpan<byte> functionName, ReadOnlySpan<byte> customization, ReadOnlySpan<byte> source, Span<byte> destination) where T : class, IXof<T>
	{
		if (typeof(T) == typeof(CShake128Xof))
		{
			CShake128Xof.HashData(functionName, customization, source, destination);
		}
		else if (typeof(T) == typeof(CShake256Xof))
		{
			CShake256Xof.HashData(functionName, customization, source, destination);
		}
		else
		{
			throw new NotSupportedException(typeof(T).Name);
		}
	}

	private static T Clone<T>(T xof) where T : class, IXof<T>
	{
		return xof switch
		{
			CShake128Xof cShake => (T)(object)cShake.Clone(),
			CShake256Xof cShake => (T)(object)cShake.Clone(),
			_ => throw new NotSupportedException(typeof(T).Name)
		};
	}

	// The output with the function name and customization string that the instances of these tests use.
	private static byte[] Output<T>(ReadOnlySpan<byte> source, int length) where T : class, IXof<T>
	{
		byte[] output = new byte[length];
		HashData<T>(Name, Customization, source, output);
		return output;
	}

	private static async Task AssertWrites(byte[] expected, OutputWriter write)
	{
		byte[] destination = new byte[expected.Length + 2];
		PrepareDestination(destination);
		write(destination.AsSpan(1, expected.Length));
		await AssertOutput(destination, 1, expected);
	}
}
