using CryptoBase.Signatures.Rsa;
using System.Diagnostics.CodeAnalysis;
using System.Numerics;
using System.Runtime;
using System.Security.Cryptography;
using static CryptoBase.Tests.Signatures.Rsa.Arithmetic.RsaArithmeticTestUtils;

namespace CryptoBase.Tests.Signatures.Rsa.Arithmetic;

// RsaPublicOperation and RsaPrivateOperation against BigInteger, with keys from the platform and keys whose primes differ in length.
public class RsaOperationTest
{
	private const ulong F4 = 65537;

	public static IEnumerable<int> PlatformKeySizes()
	{
		yield return 2048;
		yield return 3072;
		yield return 4096;
	}

	// Pairs of prime lengths: equal, one or several limbs apart, a prime of a single limb, and p above or below q.
	public static IEnumerable<(int P, int Q)> PrimeLengths()
	{
		yield return (256, 256);
		yield return (1024, 1024);
		yield return (1000, 1048);
		yield return (1048, 1000);
		yield return (512, 1536);
		yield return (1536, 512);
		yield return (64, 1984);
		yield return (1984, 64);
		yield return (33, 600);
	}

	[Test]
	public async Task PublicCreateRejectsInvalidKeys()
	{
		byte[] modulus = ToBigEndian((BigInteger.One << 1023) + 12345, 128);
		modulus[^1] |= 1;
		byte[] exponent = [1, 0, 1];

		using (Assert.Multiple())
		{
			await Assert.That(() => RsaPublicOperation.Create([], exponent)).Throws<ArgumentException>();
			await Assert.That(() => RsaPublicOperation.Create(new byte[128], exponent)).Throws<ArgumentException>();
			await Assert.That(() => RsaPublicOperation.Create([.. modulus[..^1], (byte)(modulus[^1] - 1)], exponent)).Throws<ArgumentException>();
			await Assert.That(() => RsaPublicOperation.Create(modulus, [])).Throws<ArgumentException>();
			await Assert.That(() => RsaPublicOperation.Create(modulus, [0, 0])).Throws<ArgumentException>();
			await Assert.That(() => RsaPublicOperation.Create(modulus, [1, 0, 0])).Throws<ArgumentException>();
			await Assert.That(() => RsaPublicOperation.Create(modulus, [0, 1])).Throws<ArgumentException>();
			await Assert.That(() => RsaPublicOperation.Create(ToBigEndian((BigInteger.One << 510) + 1, 64), exponent)).Throws<NotSupportedException>();
			await Assert.That(() => RsaPublicOperation.Create(ToBigEndian((BigInteger.One << 16384) + 1, 2049), exponent)).Throws<NotSupportedException>();
			await Assert.That(() => RsaPublicOperation.Create(modulus, ToBigEndian((BigInteger.One << 33) + 1, 5))).Throws<NotSupportedException>();
			await Assert.That(() => RsaPublicOperation.Create(modulus, [1, 0, 0, 0, 0, 1])).Throws<NotSupportedException>();
		}

		RsaPublicOperation smallest = RsaPublicOperation.Create([0, 0, .. ToBigEndian((BigInteger.One << 511) + 1, 64)], [0, 3]);
		RsaPublicOperation largest = RsaPublicOperation.Create(ToBigEndian((BigInteger.One << 16384) - 1, 2048), ToBigEndian((BigInteger.One << 33) - 1, 5));

		using (Assert.Multiple())
		{
			await Assert.That(smallest.ModulusBits).IsEqualTo(512);
			await Assert.That(smallest.ModulusLength).IsEqualTo(64);
			await Assert.That(smallest.ExponentLength).IsEqualTo(1);
			await Assert.That(largest.ModulusBits).IsEqualTo(16384);
			await Assert.That(largest.ModulusLength).IsEqualTo(2048);
			await Assert.That(largest.ExponentLength).IsEqualTo(5);
		}
	}

	[Test]
	public async Task PublicApplyMatchesReference()
	{
		List<string> failures = [];
		Random random = new(41);

		foreach (int bits in (ReadOnlySpan<int>)[512, 777, 2048, 4096, 16384])
		{
			BigInteger n = RandomBits(random, bits) | BigInteger.One << bits - 1 | 1;
			int length = (bits + 7) / 8;

			foreach (ulong e in (ReadOnlySpan<ulong>)[3, F4, (1UL << 33) - 1])
			{
				RsaPublicOperation key = RsaPublicOperation.Create(ToBigEndian(n, length), ToBigEndian(e, 8));
				byte[] modulus = new byte[length];
				byte[] exponent = new byte[key.ExponentLength];
				key.WriteModulus(modulus);
				key.WriteExponent(exponent);

				if (FromBigEndian(modulus) != n || FromBigEndian(exponent) != e || key.ModulusBits != bits)
				{
					failures.Add($"{bits}-bit key with e = {e}");
				}

				foreach (BigInteger x in (ReadOnlySpan<BigInteger>)[BigInteger.Zero, BigInteger.One, n - 1, RandomBelow(random, n)])
				{
					byte[] input = ToBigEndian(x, length);
					byte[] output = new byte[length];

					if (!key.TryApply(input, output) || FromBigEndian(output) != BigInteger.ModPow(x, e, n))
					{
						failures.Add($"{x:X}^{e} mod {n:X}");
					}

					if (!key.TryApply(input, input) || FromBigEndian(input) != BigInteger.ModPow(x, e, n))
					{
						failures.Add($"{x:X}^{e} mod {n:X} in place");
					}
				}

				foreach (BigInteger x in (ReadOnlySpan<BigInteger>)[n, n + 1, (BigInteger.One << 8 * length) - 1])
				{
					byte[] output = new byte[length];
					output.AsSpan().Fill(0xA5);

					if (key.TryApply(ToBigEndian(x, length), output) || output.Any(static value => value is not 0xA5))
					{
						failures.Add($"{x:X} accepted for {n:X}");
					}
				}
			}
		}

		await Assert.That(failures).IsEmpty();
	}

	[Test]
	[MethodDataSource(nameof(PlatformKeySizes))]
	public async Task ApplyMatchesReferenceForPlatformKeys(int bits)
	{
		using RSA rsa = RSA.Create(bits);
		RSAParameters parameters = rsa.ExportParameters(true);
		using RsaPrivateOperation key = Import(parameters);
		await AssertApplyMatches(key, FromBigEndian(parameters.Modulus), FromBigEndian(parameters.D), new Random(bits));
		await AssertComponents(key, parameters);
	}

	[Test]
	[MethodDataSource(nameof(PrimeLengths))]
	public async Task ApplyMatchesReferenceForUnequalPrimes(int pBits, int qBits)
	{
		Random random = new(pBits * 7 + qBits);
		TestKey key = TestKey.Generate(random, pBits, qBits, F4);
		using RsaPrivateOperation operation = key.Import();
		await AssertApplyMatches(operation, key.N, key.D, random);
	}

	[Test]
	[SuppressMessage("ReSharper", "AccessToDisposedClosure", Justification = "Assertions finish before disposal.")]
	public async Task ApplyRejectsInputsNotBelowTheModulus()
	{
		TestKey key = TestKey.Generate(new Random(42), 512, 512, F4);
		using RsaPrivateOperation operation = key.Import();
		int length = operation.PublicKey.ModulusLength;
		byte[] output = new byte[length];
		output.AsSpan().Fill(0xA5);

		using (Assert.Multiple())
		{
			await Assert.That(() => operation.Apply(ToBigEndian(key.N, length), output)).Throws<ArgumentException>();
			await Assert.That(() => operation.Apply(ToBigEndian((BigInteger.One << 8 * length) - 1, length), output)).Throws<ArgumentException>();
			await Assert.That(output.All(static value => value is 0xA5)).IsTrue();
		}
	}

	// A blinding factor that is a multiple of p or q has no inverse: with p = 3, a third of the factors are, and every signature must still come out right, as BigInteger computes it and as e takes it back.
	[Test]
	public async Task ApplyBlindsWithFactorsCoprimeToTheModulus()
	{
		TestKey key = TestKey.FromPrimes(3, (BigInteger.One << 521) - 1, F4);
		using RsaPrivateOperation operation = key.Import();
		int length = operation.PublicKey.ModulusLength;
		Random random = new(53);
		List<string> failures = [];

		for (int i = 0; i < 96; ++i)
		{
			BigInteger x = RandomBelow(random, key.N);
			byte[] output = new byte[length];

			try
			{
				operation.Apply(ToBigEndian(x, length), output);
			}
			catch (CryptographicException)
			{
				failures.Add($"{x:X}: the check failed");
				continue;
			}

			BigInteger signature = FromBigEndian(output);

			if (signature != BigInteger.ModPow(x, key.D, key.N) || BigInteger.ModPow(signature, F4, key.N) != x)
			{
				failures.Add($"{x:X}^d");
			}
		}

		await Assert.That(failures).IsEmpty();
	}

	// Composite p satisfies every congruence of the key but not RSA: the check after signing fails, and nothing is written.
	[Test]
	[SuppressMessage("ReSharper", "AccessToDisposedClosure", Justification = "Assertions finish before disposal.")]
	public async Task ApplyThrowsWhenTheCheckFails()
	{
		Random random = new(43);
		TestKey key;

		do
		{
			BigInteger p = RandomPrime(random, 256) * RandomPrime(random, 256);
			key = TestKey.FromPrimes(p, RandomPrime(random, 512), F4);
		}
		while (key.DP.IsZero);

		using RsaPrivateOperation operation = key.Import();
		int length = operation.PublicKey.ModulusLength;
		byte[] input = ToBigEndian(RandomBelow(random, key.N), length);
		byte[] output = new byte[length];
		output.AsSpan().Fill(0xA5);

		using (Assert.Multiple())
		{
			await Assert.That(() => operation.Apply(input, output)).Throws<CryptographicException>();
			await Assert.That(output.All(static value => value is 0xA5)).IsTrue();
		}
	}

	[Test]
	public async Task CreateRejectsEveryBrokenRule()
	{
		Random random = new(44);
		TestKey key = TestKey.Generate(random, 512, 512, F4);
		BigInteger otherPrime = RandomPrime(random, 512);
		BigInteger pMinusOne = key.P - 1;
		BigInteger qMinusOne = key.Q - 1;
		List<(string Rule, TestKey Key)> broken =
		[
			("p = 1", key with { P = 1, Q = key.N }),
			("p even", key with { P = key.P + 1 }),
			("q even", key with { Q = key.Q - 1 }),
			("p·q ≠ n", key with { Q = otherPrime }),
			("dP = 0", key with { DP = 0 }),
			("dP = p − 1", key with { DP = pMinusOne }),
			("dP + (p − 1)", key with { DP = key.DP + pMinusOne }),
			("e·dP ≢ 1", key with { DP = (key.DP + 2) % pMinusOne }),
			("dQ = 0", key with { DQ = 0 }),
			("dQ + (q − 1)", key with { DQ = key.DQ + qMinusOne }),
			("e·dQ ≢ 1", key with { DQ = (key.DQ + 2) % qMinusOne }),
			("qInv = 0", key with { QInv = 0 }),
			("qInv = p", key with { QInv = key.P }),
			("qInv + p", key with { QInv = key.QInv + key.P }),
			("q·qInv ≢ 1", key with { QInv = (key.QInv + 1) % key.P }),
			("d = 0", key with { D = 0 }),
			("d = n", key with { D = key.N }),
			("e·d ≢ 1 mod p − 1", key with { D = key.D + qMinusOne }),
			("e·d ≢ 1 mod q − 1", key with { D = key.D + pMinusOne }),
			("d + 1", key with { D = key.D + 1 })
		];

		List<string> accepted = [];

		foreach ((string rule, TestKey invalid) in broken)
		{
			try
			{
				invalid.Import().Dispose();
				accepted.Add(rule);
			}
			catch (ArgumentException)
			{
			}
		}

		await Assert.That(accepted).IsEmpty();
	}

	// The instance keeps copies; the buffers of the caller stay as they were, whether the key is accepted or not.
	[Test]
	public async Task CreateLeavesTheBuffersAlone()
	{
		TestKey key = TestKey.Generate(new Random(47), 512, 512, F4);
		RsaPublicOperation publicKey = RsaPublicOperation.Create(ToBigEndian(key.N, 128), ToBigEndian(key.E, 3));
		byte[][] components = [ToBigEndian(key.D, 128), ToBigEndian(key.P, 64), ToBigEndian(key.Q, 64), ToBigEndian(key.DP, 64), ToBigEndian(key.DQ, 64), ToBigEndian(key.QInv, 64)];
		byte[][] copies = [.. components.Select(static component => (byte[])component.Clone())];
		RsaPrivateOperation.Create(publicKey, components[0], components[1], components[2], components[3], components[4], components[5]).Dispose();
		await Assert.That(() => RsaPrivateOperation.Create(publicKey, components[0], components[1], components[2], components[4], components[3], components[5])).Throws<ArgumentException>();

		for (int i = 0; i < components.Length; ++i)
		{
			await Assert.That(components[i].AsSpan().SequenceEqual(copies[i])).IsTrue();
		}
	}

	// A component far shorter than the limbs that hold it has the length of its value: q ≡ 3⁻¹ (mod p) gives qInv = 3, in the limbs of p, all but the lowest of them zero.
	[Test]
	public async Task LengthsAreThoseOfTheValues()
	{
		Random random = new(52);
		BigInteger p;

		do
		{
			p = RandomPrime(random, 512);
		}
		while (!BigInteger.GreatestCommonDivisor(p - 1, F4).IsOne);

		BigInteger q = ModInverse(3, p);

		while (!IsProbablePrime(q, random) || !BigInteger.GreatestCommonDivisor(q - 1, F4).IsOne)
		{
			q += p;
		}

		TestKey key = TestKey.FromPrimes(p, q, F4);
		using RsaPrivateOperation operation = key.Import();
		(RsaPrivateComponent Component, BigInteger Value)[] components = [(RsaPrivateComponent.PrivateExponent, key.D), (RsaPrivateComponent.Prime1, p), (RsaPrivateComponent.Prime2, q), (RsaPrivateComponent.Exponent1, key.DP), (RsaPrivateComponent.Exponent2, key.DQ), (RsaPrivateComponent.Coefficient, 3)];

		using (Assert.Multiple())
		{
			await Assert.That(key.QInv).IsEqualTo(new BigInteger(3));

			foreach ((RsaPrivateComponent component, BigInteger value) in components)
			{
				await Assert.That(operation.GetLength(component)).IsEqualTo(value.GetByteCount(true)).Because(component.ToString());
				await Assert.That(Read(operation, component)).IsEqualTo(value).Because(component.ToString());
			}
		}
	}

	// d need not be the least: d + λ(n) below n holds every congruence. Leading zeros do not matter.
	[Test]
	public async Task CreateAcceptsEquivalentEncodings()
	{
		Random random = new(45);
		TestKey key = TestKey.Generate(random, 512, 512, F4);
		BigInteger lambda = (key.P - 1) * (key.Q - 1) / BigInteger.GreatestCommonDivisor(key.P - 1, key.Q - 1);
		TestKey larger = key with { D = key.D + lambda };

		await Assert.That(larger.D < key.N).IsTrue();

		using RsaPrivateOperation operation = larger.Import(leadingZeros: 3);
		await AssertApplyMatches(operation, key.N, key.D, random);
		await Assert.That(operation.GetLength(RsaPrivateComponent.PrivateExponent)).IsEqualTo(larger.D.GetByteCount(true));
	}

	[Test]
	[SuppressMessage("ReSharper", "AccessToDisposedClosure", Justification = "Parallel.For returns before disposal.")]
	public async Task ApplyRunsConcurrently()
	{
		using RSA rsa = RSA.Create(2048);
		RSAParameters parameters = rsa.ExportParameters(true);
		using RsaPrivateOperation key = Import(parameters);
		BigInteger n = FromBigEndian(parameters.Modulus);
		BigInteger d = FromBigEndian(parameters.D);
		int length = key.PublicKey.ModulusLength;
		int failures = 0;

		Parallel.For(0, 256, new ParallelOptions { MaxDegreeOfParallelism = Math.Max(Environment.ProcessorCount, 4) }, i =>
		{
			BigInteger x = RandomBelow(new Random(i), n);
			byte[] output = new byte[length];
			key.Apply(ToBigEndian(x, length), output);

			if (FromBigEndian(output) != BigInteger.ModPow(x, d, n))
			{
				Interlocked.Increment(ref failures);
			}
		});

		await Assert.That(failures).IsEqualTo(0);
	}

	// The vector kernels load and store through pointers into the buffers of each operation, which the heap may move. Private keys whose moduli and primes take each family of kernels, and a public key past every window of AVX-512, sign and verify on several threads against BigInteger while another compacts the heap again and again, with garbage left between what lives.
	[Test]
	[NotInParallel]
	[SuppressMessage("ReSharper", "AccessToDisposedClosure", Justification = "The threads are joined before disposal.")]
	public async Task ApplyStaysRightWhileTheHeapCompacts()
	{
		List<(RsaPrivateOperation Key, BigInteger N)> keys = [];
		TestKey small = TestKey.Generate(new Random(48), 256, 256, F4);
		keys.Add((small.Import(), small.N));

		foreach (int bits in (ReadOnlySpan<int>)[1024, 2048, 3072, 4096])
		{
			using RSA rsa = RSA.Create(bits);
			RSAParameters parameters = rsa.ExportParameters(true);
			keys.Add((Import(parameters), FromBigEndian(parameters.Modulus)));
		}

		BigInteger largeModulus = RandomBits(new Random(49), 16384) | BigInteger.One << 16383 | 1;
		RsaPublicOperation large = RsaPublicOperation.Create(ToBigEndian(largeModulus, 2048), ToBigEndian(F4, 3));
		long deadline = Environment.TickCount64 + 2000;
		int failures = 0;
		int operations = 0;
		int collections = 0;

		Thread compactor = new(() =>
		{
			Random random = new(50);
			Queue<ulong[]> garbage = [];

			while (Environment.TickCount64 < deadline)
			{
				for (int i = 0; i < 512; ++i)
				{
					garbage.Enqueue(new ulong[random.Next(1, 512)]);

					if (garbage.Count > 768)
					{
						garbage.Dequeue();
					}
				}

				GCSettings.LargeObjectHeapCompactionMode = GCLargeObjectHeapCompactionMode.CompactOnce;
				GC.Collect(GC.MaxGeneration, GCCollectionMode.Forced, true, true);
				Interlocked.Increment(ref collections);
			}
		});

		Thread[] workers = [.. Enumerable.Range(0, Math.Clamp(Environment.ProcessorCount / 2, 2, 8)).Select(worker => new Thread(() =>
		{
			Random random = new(worker);

			while (Environment.TickCount64 < deadline)
			{
				try
				{
					if (random.Next(keys.Count + 1) is var index && index < keys.Count)
					{
						(RsaPrivateOperation key, BigInteger n) = keys[index];
						int length = key.PublicKey.ModulusLength;
						BigInteger x = RandomBelow(random, n);
						byte[] signature = new byte[length];
						byte[] check = new byte[length];
						key.Apply(ToBigEndian(x, length), signature);

						if (!key.PublicKey.TryApply(signature, check) || FromBigEndian(check) != x || BigInteger.ModPow(FromBigEndian(signature), F4, n) != x)
						{
							Interlocked.Increment(ref failures);
						}
					}
					else
					{
						BigInteger x = RandomBelow(random, largeModulus);
						byte[] output = new byte[2048];

						if (!large.TryApply(ToBigEndian(x, 2048), output) || FromBigEndian(output) != BigInteger.ModPow(x, F4, largeModulus))
						{
							Interlocked.Increment(ref failures);
						}
					}
				}
				catch (CryptographicException)
				{
					Interlocked.Increment(ref failures);
				}

				Interlocked.Increment(ref operations);
			}
		}))];

		compactor.Start();

		foreach (Thread worker in workers)
		{
			worker.Start();
		}

		foreach (Thread worker in workers)
		{
			worker.Join();
		}

		compactor.Join();

		foreach ((RsaPrivateOperation key, _) in keys)
		{
			key.Dispose();
		}

		using (Assert.Multiple())
		{
			await Assert.That(failures).IsEqualTo(0);
			await Assert.That(operations).IsGreaterThan(workers.Length);
			await Assert.That(collections).IsGreaterThan(1);
		}
	}

	[Test]
	public async Task DisposeErasesTheKey()
	{
		TestKey key = TestKey.Generate(new Random(46), 512, 512, F4);
		RsaPrivateOperation operation = key.Import();
		RsaPublicOperation publicKey = operation.PublicKey;
		int length = publicKey.ModulusLength;
		operation.Dispose();
		operation.Dispose();
		byte[] output = new byte[length];

		using (Assert.Multiple())
		{
			await Assert.That(() => operation.Apply(new byte[length], output)).Throws<ObjectDisposedException>();
			await Assert.That(() => operation.GetLength(RsaPrivateComponent.Prime1)).Throws<ObjectDisposedException>();
			await Assert.That(() => operation.Write(RsaPrivateComponent.Prime1, new byte[64])).Throws<ObjectDisposedException>();
			await Assert.That(publicKey.TryApply(ToBigEndian(2, length), output)).IsTrue();
			await Assert.That(FromBigEndian(output)).IsEqualTo(BigInteger.ModPow(2, F4, key.N));
		}
	}

	[Test]
	public async Task GenerateRejectsInvalidArguments()
	{
		using (Assert.Multiple())
		{
			await Assert.That(() => RsaPrivateOperation.Generate(2040, F4)).Throws<ArgumentOutOfRangeException>();
			await Assert.That(() => RsaPrivateOperation.Generate(2052, F4)).Throws<ArgumentOutOfRangeException>();
			await Assert.That(() => RsaPrivateOperation.Generate(16392, F4)).Throws<ArgumentOutOfRangeException>();
			await Assert.That(() => RsaPrivateOperation.Generate(2048, 65536)).Throws<ArgumentException>();
			await Assert.That(() => RsaPrivateOperation.Generate(2048, 65535)).Throws<ArgumentException>();
			await Assert.That(() => RsaPrivateOperation.Generate(2048, 3)).Throws<ArgumentException>();
			await Assert.That(() => RsaPrivateOperation.Generate(2048, (1UL << 33) + 1)).Throws<ArgumentException>();
		}
	}

	// FIPS 186-5, Appendix A.1.1: nlen-bit n of primes of nlen/2 bits, |p − q| > 2^(nlen/2 − 100), 2^(nlen/2) < d < λ(n) with e·d ≡ 1 (mod λ(n)), GCD(p − 1, e) = GCD(q − 1, e) = 1; and the CRT values of RFC 8017, Sec. 3.2. 2056 bits leave the primes a partial limb, and a composite e takes the general GCD and inverse.
	[Test]
	[Arguments(2048, 65537UL)]
	[Arguments(2056, 255255UL)]
	[Arguments(3072, 8589934591UL)]
	public async Task GenerateMeetsFips186(int bits, ulong e)
	{
		using RsaPrivateOperation key = RsaPrivateOperation.Generate(bits, e);
		BigInteger n = Read(key.PublicKey);
		BigInteger d = Read(key, RsaPrivateComponent.PrivateExponent);
		BigInteger p = Read(key, RsaPrivateComponent.Prime1);
		BigInteger q = Read(key, RsaPrivateComponent.Prime2);
		BigInteger dP = Read(key, RsaPrivateComponent.Exponent1);
		BigInteger dQ = Read(key, RsaPrivateComponent.Exponent2);
		BigInteger qInv = Read(key, RsaPrivateComponent.Coefficient);
		BigInteger lambda = (p - 1) * (q - 1) / BigInteger.GreatestCommonDivisor(p - 1, q - 1);
		byte[] exponent = new byte[key.PublicKey.ExponentLength];
		key.PublicKey.WriteExponent(exponent);
		Random random = new(bits);

		using (Assert.Multiple())
		{
			await Assert.That(FromBigEndian(exponent)).IsEqualTo(e);
			await Assert.That(key.PublicKey.ModulusBits).IsEqualTo(bits);
			await Assert.That(n).IsEqualTo(p * q);
			await Assert.That(p.GetBitLength()).IsEqualTo(bits / 2);
			await Assert.That(q.GetBitLength()).IsEqualTo(bits / 2);
			await Assert.That(BigInteger.Abs(p - q) > BigInteger.One << bits / 2 - 100).IsTrue();
			await Assert.That(IsProbablePrime(p, random)).IsTrue();
			await Assert.That(IsProbablePrime(q, random)).IsTrue();
			await Assert.That(BigInteger.GreatestCommonDivisor(p - 1, e).IsOne && BigInteger.GreatestCommonDivisor(q - 1, e).IsOne).IsTrue();
			await Assert.That(d > BigInteger.One << bits / 2 && d < lambda).IsTrue();
			await Assert.That((e * d % lambda).IsOne).IsTrue();
			await Assert.That(dP).IsEqualTo(d % (p - 1));
			await Assert.That(dQ).IsEqualTo(d % (q - 1));
			await Assert.That(q * qInv % p).IsEqualTo(BigInteger.One);
		}

		await AssertApplyMatches(key, n, d, random);
	}

	[Test]
	public async Task RoundsFollowTableB1()
	{
		using (Assert.Multiple())
		{
			await Assert.That(CryptoBase.Signatures.Rsa.Arithmetic.ProbablePrime.GetRounds(1024)).IsEqualTo(5);
			await Assert.That(CryptoBase.Signatures.Rsa.Arithmetic.ProbablePrime.GetRounds(1028)).IsEqualTo(5);
			await Assert.That(CryptoBase.Signatures.Rsa.Arithmetic.ProbablePrime.GetRounds(1536)).IsEqualTo(4);
			await Assert.That(CryptoBase.Signatures.Rsa.Arithmetic.ProbablePrime.GetRounds(2048)).IsEqualTo(4);
			await Assert.That(CryptoBase.Signatures.Rsa.Arithmetic.ProbablePrime.GetRounds(8192)).IsEqualTo(4);
		}
	}

	private static async Task AssertApplyMatches(RsaPrivateOperation key, BigInteger n, BigInteger d, Random random)
	{
		int length = key.PublicKey.ModulusLength;
		List<string> failures = [];

		foreach (BigInteger x in (ReadOnlySpan<BigInteger>)[BigInteger.Zero, BigInteger.One, n - 1, RandomBelow(random, n), RandomBelow(random, n)])
		{
			byte[] input = ToBigEndian(x, length);
			byte[] output = new byte[length];
			BigInteger expected = BigInteger.ModPow(x, d, n);
			key.Apply(input, output);

			if (FromBigEndian(output) != expected)
			{
				failures.Add($"{x:X}^d");
			}

			key.Apply(input, input);

			if (FromBigEndian(input) != expected)
			{
				failures.Add($"{x:X}^d in place");
			}
		}

		await Assert.That(failures).IsEmpty();
	}

	private static async Task AssertComponents(RsaPrivateOperation key, RSAParameters parameters)
	{
		using (Assert.Multiple())
		{
			await Assert.That(Read(key, RsaPrivateComponent.PrivateExponent)).IsEqualTo(FromBigEndian(parameters.D));
			await Assert.That(Read(key, RsaPrivateComponent.Prime1)).IsEqualTo(FromBigEndian(parameters.P));
			await Assert.That(Read(key, RsaPrivateComponent.Prime2)).IsEqualTo(FromBigEndian(parameters.Q));
			await Assert.That(Read(key, RsaPrivateComponent.Exponent1)).IsEqualTo(FromBigEndian(parameters.DP));
			await Assert.That(Read(key, RsaPrivateComponent.Exponent2)).IsEqualTo(FromBigEndian(parameters.DQ));
			await Assert.That(Read(key, RsaPrivateComponent.Coefficient)).IsEqualTo(FromBigEndian(parameters.InverseQ));
		}
	}

	private static BigInteger Read(RsaPrivateOperation key, RsaPrivateComponent component)
	{
		byte[] value = new byte[key.GetLength(component)];
		key.Write(component, value);

		if (value.Length > 0 && value[0] is 0)
		{
			throw new InvalidOperationException("A leading zero was written.");
		}

		return FromBigEndian(value);
	}

	private static BigInteger Read(RsaPublicOperation key)
	{
		byte[] modulus = new byte[key.ModulusLength];
		key.WriteModulus(modulus);
		return FromBigEndian(modulus);
	}

	private static RsaPrivateOperation Import(RSAParameters parameters)
	{
		RsaPublicOperation publicKey = RsaPublicOperation.Create(parameters.Modulus, parameters.Exponent);
		return RsaPrivateOperation.Create(publicKey, parameters.D, parameters.P, parameters.Q, parameters.DP, parameters.DQ, parameters.InverseQ);
	}

	private sealed record TestKey(BigInteger N, ulong E, BigInteger D, BigInteger P, BigInteger Q, BigInteger DP, BigInteger DQ, BigInteger QInv)
	{
		internal static TestKey Generate(Random random, int pBits, int qBits, ulong e)
		{
			while (true)
			{
				BigInteger p = RandomPrime(random, pBits);
				BigInteger q = RandomPrime(random, qBits);

				if (p != q && (p * q).GetBitLength() >= 512 && BigInteger.GreatestCommonDivisor(p - 1, e).IsOne && BigInteger.GreatestCommonDivisor(q - 1, e).IsOne)
				{
					return FromPrimes(p, q, e);
				}
			}
		}

		// d, dP and dQ are zero if e has no inverse, which callers that want a working key avoid.
		internal static TestKey FromPrimes(BigInteger p, BigInteger q, ulong e)
		{
			BigInteger lambda = (p - 1) * (q - 1) / BigInteger.GreatestCommonDivisor(p - 1, q - 1);
			BigInteger d = BigInteger.GreatestCommonDivisor(lambda, e).IsOne ? ModInverse(e, lambda) : 0;
			BigInteger dP = BigInteger.GreatestCommonDivisor(p - 1, e).IsOne ? ModInverse(e, p - 1) : 0;
			BigInteger dQ = BigInteger.GreatestCommonDivisor(q - 1, e).IsOne ? ModInverse(e, q - 1) : 0;
			return new TestKey(p * q, e, d, p, q, dP, dQ, ModInverse(q, p));
		}

		internal RsaPrivateOperation Import()
		{
			return Import(0);
		}

		internal RsaPrivateOperation Import(int leadingZeros)
		{
			RsaPublicOperation publicKey = RsaPublicOperation.Create(Encode(N, leadingZeros), Encode(E, leadingZeros));
			return RsaPrivateOperation.Create(publicKey, Encode(D, leadingZeros), Encode(P, leadingZeros), Encode(Q, leadingZeros), Encode(DP, leadingZeros), Encode(DQ, leadingZeros), Encode(QInv, leadingZeros));
		}

		private static byte[] Encode(BigInteger value, int leadingZeros)
		{
			return ToBigEndian(value, value.GetByteCount(true) + leadingZeros);
		}
	}
}
