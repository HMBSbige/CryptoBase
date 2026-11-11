using CryptoBase.Abstractions.Hashes;
using CryptoBase.Hashes;
using CryptoBase.Hashes.Blake2;
using CryptoBase.Hashes.Blake3;
using CryptoBase.Hashes.Crc32;
using CryptoBase.Hashes.MD5;
using CryptoBase.Hashes.Sha1;
using CryptoBase.Hashes.Sha2;
using CryptoBase.Hashes.Sha3;
using CryptoBase.Hashes.SM3;
using CryptoBase.Macs.Hmac;
using CryptoBase.Tests.Hashes.Blake3;
using System.Diagnostics.CodeAnalysis;
using System.Reflection;
using static CryptoBase.Tests.TestUtils;

namespace CryptoBase.Tests.IO;

/// <summary>
/// The stream extensions append an empty span to learn whether the algorithm has been disposed, so an empty append must not change any later output.
/// </summary>
public class EmptyAppendTest
{
	private const int Read = -1;
	private const int ReadAndReset = -2;

	// Lengths straddle 64- and 128-byte blocks, and the BLAKE3 chunk (1 KiB) and group (16 KiB); reads in between put BLAKE3 into chunk mode.
	private static readonly int[][] Operations =
	[
		[Read],
		[1, Read],
		[63, 1, Read, 64, Read, 65, Read],
		[127, Read, 1, 129, ReadAndReset, 3, Read],
		[100, Read, 10, Read, 70, Read, 1000, Read, 5000, Read],
		[1023, Read, 1, Read, 1024, Read, 2049, Read],
		[3000, Read, 16384 + 5, Read, 7, ReadAndReset, Read],
		[16384, 16384, 1, Read, 2, Read, 40000, ReadAndReset, 1024, Read]
	];

	private static readonly FieldInfo ChunkModeField = typeof(Blake3HashAlgorithm).GetField("_chunkMode", BindingFlags.Instance | BindingFlags.NonPublic)!;

	// The cores, each with its run; EveryHashCoreIsCovered keeps them complete.
	private static readonly Dictionary<Type, Func<int[], bool, List<byte[]>>> HashAlgorithmRuns = new()
	{
		[typeof(Blake2b256Core)] = RunHashAlgorithm<Blake2b256Core>,
		[typeof(Blake2b512Core)] = RunHashAlgorithm<Blake2b512Core>,
		[typeof(Crc32CCore)] = RunHashAlgorithm<Crc32CCore>,
		[typeof(Crc32Core)] = RunHashAlgorithm<Crc32Core>,
		[typeof(MD5Core)] = RunHashAlgorithm<MD5Core>,
		[typeof(SM3Core)] = RunHashAlgorithm<SM3Core>,
		[typeof(Sha1Core)] = RunHashAlgorithm<Sha1Core>,
		[typeof(Sha224Core)] = RunHashAlgorithm<Sha224Core>,
		[typeof(Sha256Core)] = RunHashAlgorithm<Sha256Core>,
		[typeof(Sha384Core)] = RunHashAlgorithm<Sha384Core>,
		[typeof(Sha512Core)] = RunHashAlgorithm<Sha512Core>,
		[typeof(Sha3_224Core)] = RunHashAlgorithm<Sha3_224Core>,
		[typeof(Sha3_256Core)] = RunHashAlgorithm<Sha3_256Core>,
		[typeof(Sha3_384Core)] = RunHashAlgorithm<Sha3_384Core>,
		[typeof(Sha3_512Core)] = RunHashAlgorithm<Sha3_512Core>
	};

	private static readonly Dictionary<Type, Func<byte[], int[], bool, List<byte[]>>> HmacAlgorithmRuns = new()
	{
		[typeof(Blake2b256Core)] = RunHmacAlgorithm<Blake2b256Core>,
		[typeof(Blake2b512Core)] = RunHmacAlgorithm<Blake2b512Core>,
		[typeof(MD5Core)] = RunHmacAlgorithm<MD5Core>,
		[typeof(SM3Core)] = RunHmacAlgorithm<SM3Core>,
		[typeof(Sha1Core)] = RunHmacAlgorithm<Sha1Core>,
		[typeof(Sha224Core)] = RunHmacAlgorithm<Sha224Core>,
		[typeof(Sha256Core)] = RunHmacAlgorithm<Sha256Core>,
		[typeof(Sha384Core)] = RunHmacAlgorithm<Sha384Core>,
		[typeof(Sha512Core)] = RunHmacAlgorithm<Sha512Core>,
		[typeof(Sha3_224Core)] = RunHmacAlgorithm<Sha3_224Core>,
		[typeof(Sha3_256Core)] = RunHmacAlgorithm<Sha3_256Core>,
		[typeof(Sha3_384Core)] = RunHmacAlgorithm<Sha3_384Core>,
		[typeof(Sha3_512Core)] = RunHmacAlgorithm<Sha3_512Core>
	};

	public static IEnumerable<Func<Type>> HashCores()
	{
		return HashAlgorithmRuns.Keys.Select(static type => (Func<Type>)(() => type));
	}

	public static IEnumerable<Func<Type>> HmacHashCores()
	{
		return HmacAlgorithmRuns.Keys.Select(static type => (Func<Type>)(() => type));
	}

	[Test]
	public async Task EveryHashCoreIsCovered()
	{
		SkipUnlessJit();

		using (Assert.Multiple())
		{
			await Assert.That(HashAlgorithmRuns.Keys).IsEquivalentTo(ImplementationsOfSelf(typeof(IHashCore<>)));
			await Assert.That(HmacAlgorithmRuns.Keys).IsEquivalentTo(ImplementationsOfSelf(typeof(IHmacHashCore<>)));
		}
	}

	[Test]
	[MethodDataSource(nameof(HashCores))]
	public async Task HashAlgorithmIgnoresEmptyAppend(Type core)
	{
		Func<int[], bool, List<byte[]>> run = HashAlgorithmRuns[core];

		foreach (int[] operations in Operations)
		{
			List<byte[]> expected = run(operations, false);
			List<byte[]> actual = run(operations, true);
			await AssertSameOutputs(actual, expected);
		}
	}

	[Test]
	[MethodDataSource(nameof(HmacHashCores))]
	public async Task HmacAlgorithmIgnoresEmptyAppend(Type core)
	{
		Func<byte[], int[], bool, List<byte[]>> run = HmacAlgorithmRuns[core];

		foreach (int keyLength in new[] { 0, 32, 200 })
		{
			byte[] key = CreateDeterministicSource(keyLength);

			foreach (int[] operations in Operations)
			{
				List<byte[]> expected = run(key, operations, false);
				List<byte[]> actual = run(key, operations, true);
				await AssertSameOutputs(actual, expected);
			}
		}
	}

	[Test]
	[MethodDataSource(typeof(Blake3TestUtils), nameof(Blake3TestUtils.Modes))]
	public async Task Blake3IgnoresEmptyAppendInEveryState(Blake3Mode mode)
	{
		bool sawChunkMode = false;
		bool sawGroupModeAfterRead = false;

		foreach (int[] operations in Operations)
		{
			List<byte[]> expected = RunBlake3(mode, operations, false, ref sawChunkMode, ref sawGroupModeAfterRead);
			List<byte[]> actual = RunBlake3(mode, operations, true, ref sawChunkMode, ref sawGroupModeAfterRead);
			await AssertSameOutputs(actual, expected);
		}

		// Proves that the operations reach both modes, so the empty appends above ran in each.
		using (Assert.Multiple())
		{
			await Assert.That(sawChunkMode).IsTrue();
			await Assert.That(sawGroupModeAfterRead).IsTrue();
		}
	}

	private static List<byte[]> RunHashAlgorithm<TCore>(int[] operations, bool appendEmpty) where TCore : unmanaged, IHashCore<TCore>
	{
		using HashAlgorithm<TCore> hasher = HashAlgorithm<TCore>.Create();
		return Run(hasher.Append, hasher.GetCurrentHash, hasher.GetHashAndReset, HashAlgorithm<TCore>.HashLength, operations, appendEmpty, null);
	}

	private static List<byte[]> RunHmacAlgorithm<TCore>(byte[] key, int[] operations, bool appendEmpty) where TCore : unmanaged, IHmacHashCore<TCore>
	{
		using HmacAlgorithm<TCore> mac = HmacAlgorithm<TCore>.Create(key);
		return Run(mac.Append, mac.GetCurrentMac, mac.GetMacAndReset, HmacAlgorithm<TCore>.MacLength, operations, appendEmpty, null);
	}

	[SuppressMessage("ReSharper", "AccessToDisposedClosure", Justification = "Run calls observe only before it returns, while the hasher is alive.")]
	private static List<byte[]> RunBlake3(Blake3Mode mode, int[] operations, bool appendEmpty, ref bool sawChunkMode, ref bool sawGroupModeAfterRead)
	{
		using Blake3HashAlgorithm hasher = Blake3TestUtils.CreateHasher(mode);
		IHashAlgorithm<Blake3HashAlgorithm> algorithm = hasher;
		bool chunkMode = false;
		bool groupModeAfterRead = false;
		bool afterRead = false;

		List<byte[]> outputs = Run(hasher.Append, algorithm.GetCurrentHash, algorithm.GetHashAndReset, Blake3HashAlgorithm.HashLength, operations, appendEmpty, operation =>
		{
			bool isChunkMode = (bool)ChunkModeField.GetValue(hasher)!;
			chunkMode |= isChunkMode;
			groupModeAfterRead |= afterRead && operation > 0 && !isChunkMode;
			afterRead = operation is Read;
		});

		sawChunkMode |= chunkMode;
		sawGroupModeAfterRead |= groupModeAfterRead;
		return outputs;
	}

	private delegate void AppendSpan(ReadOnlySpan<byte> source);

	private delegate int WriteOutput(Span<byte> destination);

	// Records every output; with appendEmpty, appends an empty span before and after every operation and then lets observe see the state.
	private static List<byte[]> Run(AppendSpan append, WriteOutput getCurrent, WriteOutput getAndReset, int outputLength, int[] operations, bool appendEmpty, Action<int>? observe)
	{
		List<byte[]> outputs = [];
		int offset = 0;
		byte[] source = CreateDeterministicSource(operations.Where(static operation => operation > 0).Sum());

		foreach (int operation in operations)
		{
			if (appendEmpty)
			{
				append(ReadOnlySpan<byte>.Empty);
			}

			switch (operation)
			{
				case Read:
				{
					outputs.Add(Write(getCurrent, outputLength));
					break;
				}
				case ReadAndReset:
				{
					outputs.Add(Write(getAndReset, outputLength));
					break;
				}
				default:
				{
					append(source.AsSpan(offset, operation));
					offset += operation;
					break;
				}
			}

			if (appendEmpty)
			{
				append(ReadOnlySpan<byte>.Empty);
				observe?.Invoke(operation);
			}
		}

		outputs.Add(Write(getCurrent, outputLength));
		return outputs;
	}

	private static byte[] Write(WriteOutput write, int outputLength)
	{
		byte[] output = new byte[outputLength];
		write(output);
		return output;
	}

	private static async Task AssertSameOutputs(List<byte[]> actual, List<byte[]> expected)
	{
		await Assert.That(actual.Count).IsEqualTo(expected.Count);

		for (int i = 0; i < expected.Count; ++i)
		{
			await Assert.That(actual[i]).IsEquivalentTo(expected[i], CollectionOrdering.Matching);
		}
	}

	private static IEnumerable<Type> ImplementationsOfSelf(Type genericInterface)
	{
		return typeof(Sha256Core).Assembly.GetTypes()
			.Where(type => type is { IsValueType: true, IsGenericTypeDefinition: false }
				&& type.GetInterfaces().Any(i => i.IsGenericType && i.GetGenericTypeDefinition() == genericInterface && i.GenericTypeArguments[0] == type))
			.OrderBy(static type => type.FullName, StringComparer.Ordinal);
	}
}
