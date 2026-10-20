using CryptoBase.Abstractions.Kems;
using CryptoBase.Hashes;
using CryptoBase.Hashes.Sha3;
using CryptoBase.Internal;
using CryptoBase.Kems.MLKem;
using CryptoBase.Tests.Hashes.Sha3;
using System.Buffers.Binary;
using System.Diagnostics;
using System.Reflection;
using System.Runtime.InteropServices;
using static CryptoBase.Tests.Kems.KemTestUtils;
using static CryptoBase.Tests.TestUtils;

namespace CryptoBase.Tests.Kems.MLKem;

public class MLKemTest
{
	// A ciphertext that does not re-encrypt to itself yields K̄ = J(z ‖ c) (Algorithm 18, lines 8 to 11), z being the last 32 bytes of dk.
	[Test]
	[GenerateGenericTest(typeof(MLKem512))]
	[GenerateGenericTest(typeof(MLKem768))]
	[GenerateGenericTest(typeof(MLKem1024))]
	public async Task RejectionYieldsTheHashOfZAndTheCiphertext<T>() where T : class, IKem<T>
	{
		using T kem = T.GenerateKey();
		byte[] z = ExportDecapsulationKey(kem).AsSpan(T.DecapsulationKeyLength - 32).ToArray();
		byte[] ciphertext = Encapsulate(kem).Ciphertext;
		List<int> mismatches = [];
		int index = 0;

		foreach (byte[] tampered in Tampered(ciphertext))
		{
			byte[] expected = new byte[T.SharedSecretLength];
			Xof<Shake256HashAlgorithm>.HashData(Concat(z, tampered), expected);

			if (!Decapsulate(kem, tampered).AsSpan().SequenceEqual(expected))
			{
				mismatches.Add(index);
			}

			++index;
		}

		await Assert.That(mismatches).IsEmpty();
	}

	// An entry of Â that three SHAKE128 blocks leave short squeezes more after its group. Grouping depends on the parameter and
	// instruction sets, so a seed is searched that leaves each entry short.
	[Test]
	[GenerateGenericTest(typeof(MLKem512))]
	[GenerateGenericTest(typeof(MLKem768))]
	[GenerateGenericTest(typeof(MLKem1024))]
	public async Task MatrixEntriesThatNeedMoreBlocksMatchTheReference<T>() where T : class, IKem<T>
	{
		int k = (T.EncapsulationKeyLength - 32) / 384;
		int eta1 = k is 2 ? 3 : 2;
		byte[] z = CreateDeterministicSource(32);
		byte[] message = CreateDeterministicSource(33).AsSpan(1).ToArray();

		foreach ((int row, int column, byte[] d) in SeedsLeavingEachEntryShort(k))
		{
			string entry = $"entry ({row}, {column}) of Â^T";
			using T generated = T.ImportPrivateSeed(Concat(d, z));
			byte[] encapsulationKey = ExportEncapsulationKey(generated);
			byte[] decapsulationKey = ExportDecapsulationKey(generated);
			using T fromEncapsulationKey = T.ImportEncapsulationKey(encapsulationKey);
			using T fromDecapsulationKey = T.ImportDecapsulationKey(decapsulationKey);
			(byte[] ciphertext, byte[] sharedSecret) = MLKemTestUtils.Encapsulate(generated, message);
			byte[] importedCiphertext = MLKemTestUtils.Encapsulate(fromEncapsulationKey, message).Ciphertext;

			using (Assert.Multiple())
			{
				await Assert.That(encapsulationKey).IsEquivalentTo(MLKemReference.EncapsulationKey(d, k, eta1), CollectionOrdering.Matching).Because(entry);
				await Assert.That(decapsulationKey.AsSpan(768 * k + 32, 32).ToArray()).IsEquivalentTo(KeccakReference.Sha3(encapsulationKey, 32), CollectionOrdering.Matching).Because(entry);
				await Assert.That(importedCiphertext).IsEquivalentTo(ciphertext, CollectionOrdering.Matching).Because(entry);
				await Assert.That(Decapsulate(fromDecapsulationKey, ciphertext)).IsEquivalentTo(sharedSecret, CollectionOrdering.Matching).Because(entry);
			}
		}
	}

	[Test]
	[GenerateGenericTest(typeof(MLKem512))]
	[GenerateGenericTest(typeof(MLKem768))]
	[GenerateGenericTest(typeof(MLKem1024))]
	public async Task DisposeErasesTheKey<T>() where T : class, IKem<T>
	{
		T generated = T.GenerateKey();
		T fromDecapsulationKey = T.ImportDecapsulationKey(ExportDecapsulationKey(generated));
		T fromEncapsulationKey = T.ImportEncapsulationKey(ExportEncapsulationKey(generated));

		foreach (T kem in (T[])[generated, fromDecapsulationKey, fromEncapsulationKey])
		{
			List<short[]> arrays = [];
			Dictionary<string, int> before = KeyContents(kem, arrays);
			kem.Dispose();
			Dictionary<string, int> after = KeyContents(kem, []);

			using (Assert.Multiple())
			{
				await Assert.That(before.Values.Sum()).IsPositive();
				await Assert.That(after.Values).All(static count => count is 0);
				await Assert.That(arrays).IsNotEmpty();
				await Assert.That(arrays).All(static array => !array.AsSpan().ContainsAnyExcept((short)0));
			}
		}

		// A key that has used H(ek) fills every field, so the test cannot pass on fields that are always empty.
		using T full = T.GenerateKey();
		Decapsulate(full, new byte[T.CiphertextLength]);
		Dictionary<string, int> fullContents = KeyContents(full, []);
		fullContents.Remove("_partialEncapsulationKeyHash");
		fullContents.Remove("_encapsulationKeyHashAbsorbed");
		await Assert.That(fullContents.Values).All(static count => count > 0);
	}

	// Whichever use of H(ek) comes first finishes it; all must agree with later calls, an import of dk and the reference.
	[Test]
	[GenerateGenericTest(typeof(MLKem512))]
	[GenerateGenericTest(typeof(MLKem768))]
	[GenerateGenericTest(typeof(MLKem1024))]
	public async Task FirstUseOfAGeneratedKeyFinishesTheHashOfTheEncapsulationKey<T>() where T : class, IKem<T>
	{
		int k = (T.EncapsulationKeyLength - 32) / 384;
		int eta1 = k is 2 ? 3 : 2;
		byte[] seed = CreateDeterministicSource(T.PrivateSeedLength);
		byte[] message = CreateDeterministicSource(33).AsSpan(1).ToArray();
		byte[] encapsulationKey = MLKemReference.EncapsulationKey(seed.AsSpan(0, 32), k, eta1);
		byte[] encapsulationKeyHash = KeccakReference.Sha3(encapsulationKey, 32);
		using T peer = T.ImportEncapsulationKey(encapsulationKey);
		(byte[] ciphertext, byte[] sharedSecret) = MLKemTestUtils.Encapsulate(peer, message);
		byte[] tampered = (byte[])ciphertext.Clone();
		tampered[0] ^= 1;
		byte[] rejected = new byte[T.SharedSecretLength];
		Xof<Shake256HashAlgorithm>.HashData(Concat(seed.AsSpan(32), tampered), rejected);

		using T decapsulatedFirst = T.ImportPrivateSeed(seed);
		byte[] firstSharedSecret = Decapsulate(decapsulatedFirst, ciphertext);
		byte[] laterSharedSecret = Decapsulate(decapsulatedFirst, ciphertext);
		byte[] laterRejected = Decapsulate(decapsulatedFirst, tampered);
		byte[] decapsulationKey = ExportDecapsulationKey(decapsulatedFirst);

		using T rejectedFirst = T.ImportPrivateSeed(seed);
		byte[] firstRejected = Decapsulate(rejectedFirst, tampered);

		using T exportedFirst = T.ImportPrivateSeed(seed);
		byte[] firstDecapsulationKey = ExportDecapsulationKey(exportedFirst);
		byte[] sharedSecretAfterExport = Decapsulate(exportedFirst, ciphertext);

		using T encapsulatedFirst = T.ImportPrivateSeed(seed);
		(byte[] firstCiphertext, byte[] firstEncapsulatedSecret) = MLKemTestUtils.Encapsulate(encapsulatedFirst, message);
		byte[] decapsulationKeyAfterEncapsulation = ExportDecapsulationKey(encapsulatedFirst);

		using T imported = T.ImportDecapsulationKey(firstDecapsulationKey);

		using (Assert.Multiple())
		{
			await Assert.That(firstSharedSecret).IsEquivalentTo(sharedSecret, CollectionOrdering.Matching);
			await Assert.That(laterSharedSecret).IsEquivalentTo(sharedSecret, CollectionOrdering.Matching);
			await Assert.That(firstRejected).IsEquivalentTo(rejected, CollectionOrdering.Matching);
			await Assert.That(laterRejected).IsEquivalentTo(rejected, CollectionOrdering.Matching);
			await Assert.That(firstDecapsulationKey.AsSpan(384 * k, encapsulationKey.Length).ToArray()).IsEquivalentTo(encapsulationKey, CollectionOrdering.Matching);
			await Assert.That(firstDecapsulationKey.AsSpan(768 * k + 32, 32).ToArray()).IsEquivalentTo(encapsulationKeyHash, CollectionOrdering.Matching);
			await Assert.That(decapsulationKey).IsEquivalentTo(firstDecapsulationKey, CollectionOrdering.Matching);
			await Assert.That(decapsulationKeyAfterEncapsulation).IsEquivalentTo(firstDecapsulationKey, CollectionOrdering.Matching);
			await Assert.That(sharedSecretAfterExport).IsEquivalentTo(sharedSecret, CollectionOrdering.Matching);
			await Assert.That(firstCiphertext).IsEquivalentTo(ciphertext, CollectionOrdering.Matching);
			await Assert.That(firstEncapsulatedSecret).IsEquivalentTo(sharedSecret, CollectionOrdering.Matching);
			await Assert.That(Decapsulate(imported, ciphertext)).IsEquivalentTo(sharedSecret, CollectionOrdering.Matching);
			await Assert.That(Decapsulate(imported, tampered)).IsEquivalentTo(rejected, CollectionOrdering.Matching);
			await Assert.That(ExportDecapsulationKey(imported)).IsEquivalentTo(firstDecapsulationKey, CollectionOrdering.Matching);
		}
	}

	// Concurrent first uses finish H(ek) without a lock.
	[Test]
	[GenerateGenericTest(typeof(MLKem512))]
	[GenerateGenericTest(typeof(MLKem768))]
	[GenerateGenericTest(typeof(MLKem1024))]
	public async Task ConcurrentFirstUsesOfAGeneratedKeyAgree<T>() where T : class, IKem<T>
	{
		const int Threads = 8;
		const int Keys = 16;
		const int Calls = 4;
		byte[] seed = CreateDeterministicSource(T.PrivateSeedLength);
		byte[] ciphertext;
		byte[] sharedSecret;
		byte[] decapsulationKey;

		using (T reference = T.ImportPrivateSeed(seed))
		{
			(ciphertext, sharedSecret) = Encapsulate(reference);
			decapsulationKey = ExportDecapsulationKey(reference);
		}

		int mismatches = 0;

		for (int i = 0; i < Keys; ++i)
		{
			using T kem = T.ImportPrivateSeed(seed);
			using Barrier barrier = new(Threads);
			Task<int>[] tasks = new Task<int>[Threads];

			for (int thread = 0; thread < Threads; ++thread)
			{
				// One thread in four exports dk rather than decapsulates, so that both first uses race.
				bool exports = thread % 4 is 3;
				// Passed as state so that the lambda does not capture disposables.
				tasks[thread] = Task.Factory.StartNew(state =>
				{
					(T instance, Barrier start) = ((T, Barrier))state!;
					start.SignalAndWait();
					int threadMismatches = 0;

					for (int call = 0; call < Calls; ++call)
					{
						bool matches = exports ? ExportDecapsulationKey(instance).AsSpan().SequenceEqual(decapsulationKey) : Decapsulate(instance, ciphertext).AsSpan().SequenceEqual(sharedSecret);

						if (!matches)
						{
							++threadMismatches;
						}
					}

					return threadMismatches;
				}, (kem, barrier), CancellationToken.None, TaskCreationOptions.LongRunning, TaskScheduler.Default);
			}

			mismatches += (await Task.WhenAll(tasks)).Sum();
		}

		await Assert.That(mismatches).IsZero();
	}

	[Test]
	[GenerateGenericTest(typeof(MLKem512))]
	[GenerateGenericTest(typeof(MLKem768))]
	[GenerateGenericTest(typeof(MLKem1024))]
	public async Task KeyOperationsDoNotAllocate<T>() where T : class, IKem<T>
	{
		// Without optimization, every read of a constant ReadOnlySpan<short>, such as the zetas, allocates a field handle.
		if (typeof(T).Assembly.GetCustomAttribute<DebuggableAttribute>()?.IsJITOptimizerDisabled is true)
		{
			Skip.Test("The implementation is not optimized.");
		}

		using T kem = T.GenerateKey();
		byte[] seed = new byte[T.PrivateSeedLength];
		byte[] decapsulationKey = new byte[T.DecapsulationKeyLength];
		byte[] encapsulationKey = new byte[T.EncapsulationKeyLength];
		byte[] ciphertext = new byte[T.CiphertextLength];
		byte[] sharedSecret = new byte[T.SharedSecretLength];
		byte[] decapsulated = new byte[T.SharedSecretLength];

		Exercise(kem, seed, decapsulationKey, encapsulationKey, ciphertext, sharedSecret, decapsulated);
		long before = GC.GetAllocatedBytesForCurrentThread();
		Exercise(kem, seed, decapsulationKey, encapsulationKey, ciphertext, sharedSecret, decapsulated);
		long allocated = GC.GetAllocatedBytesForCurrentThread() - before;

		using (Assert.Multiple())
		{
			await Assert.That(allocated).IsZero();
			await Assert.That(decapsulated).IsEquivalentTo(sharedSecret, CollectionOrdering.Matching);
		}
	}

	// For each entry (i, j) of Â^T, SampleNTT(ρ ‖ i ‖ j), the first of the seeds d = 0, 1, 2, ... (little-endian) whose three SHAKE128
	// blocks for that entry hold fewer than 256 coefficients.
	private static List<(int Row, int Column, byte[] D)> SeedsLeavingEachEntryShort(int k)
	{
		List<(int, int, byte[])> seeds = [];
		bool[] found = new bool[k * k];
		byte[] rhoSigma = new byte[64];
		byte[] blocks = new byte[3 * 168];

		for (int counter = 0; seeds.Count < k * k; ++counter)
		{
			if (counter > 100_000)
			{
				throw new InvalidOperationException("No seed found that leaves every entry short.");
			}

			byte[] d = new byte[32];
			BinaryPrimitives.WriteInt32LittleEndian(d, counter);
			HashAlgorithm<Sha3_512HashAlgorithm>.HashData([.. d, (byte)k], rhoSigma);

			for (int entry = 0; entry < k * k; ++entry)
			{
				int row = entry / k;
				int column = entry % k;
				Xof<Shake128HashAlgorithm>.HashData([.. rhoSigma.AsSpan(0, 32), (byte)row, (byte)column], blocks);

				if (!found[entry] && MLKemReference.RejectSample(blocks, 256).Count < 256)
				{
					found[entry] = true;
					seeds.Add((row, column, d));
				}
			}
		}

		return seeds;
	}

	private static void Exercise<T>(T kem, byte[] seed, byte[] decapsulationKey, byte[] encapsulationKey, byte[] ciphertext, byte[] sharedSecret, byte[] decapsulated) where T : class, IKem<T>
	{
		for (int i = 0; i < 4; ++i)
		{
			kem.ExportPrivateSeed(seed);
			kem.ExportDecapsulationKey(decapsulationKey);
			kem.ExportEncapsulationKey(encapsulationKey);
			kem.Encapsulate(ciphertext, sharedSecret);
			kem.Decapsulate(ciphertext, decapsulated);
		}
	}

	// The number of nonzero elements or set flags in each field of the key an instance holds; arrays receives the arrays it references.
	private static Dictionary<string, int> KeyContents<T>(T kem, List<short[]> arrays) where T : class, IKem<T>
	{
		FieldInfo? keyField = typeof(T).GetField("_key", BindingFlags.Instance | BindingFlags.NonPublic);
		object key = keyField?.GetValue(kem) ?? throw new InvalidOperationException($"{typeof(T).Name} has no key field.");
		Dictionary<string, int> contents = [];

		foreach (FieldInfo field in key.GetType().GetFields(BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic))
		{
			object? value = field.GetValue(key);

			switch (value)
			{
				case short[] array:
				{
					arrays.Add(array);
					contents[field.Name] = array.Length - array.AsSpan().Count((short)0);
					break;
				}
				case InlineArray32<byte> bytes:
				{
					contents[field.Name] = CountNonZero(bytes);
					break;
				}
				case KeccakSponge<KeccakRate136> sponge:
				{
					ReadOnlySpan<byte> bytes = MemoryMarshal.AsBytes(new ReadOnlySpan<KeccakSponge<KeccakRate136>>(in sponge));
					contents[field.Name] = bytes.Length - bytes.Count((byte)0);
					break;
				}
				case int number:
				{
					contents[field.Name] = number is 0 ? 0 : 1;
					break;
				}
				case bool flag:
				{
					contents[field.Name] = flag ? 1 : 0;
					break;
				}
				default:
				{
					throw new InvalidOperationException($"The test does not know how to check {field.Name}.");
				}
			}
		}

		return contents;
	}

	private static int CountNonZero(InlineArray32<byte> value)
	{
		ReadOnlySpan<byte> bytes = value;
		return bytes.Length - bytes.Count((byte)0);
	}
}
