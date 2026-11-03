using CryptoBase.Signatures.Rsa.Arithmetic;
using System.Numerics;
using System.Runtime.CompilerServices;
using static CryptoBase.Tests.Signatures.Rsa.Arithmetic.RsaArithmeticTestUtils;
using static CryptoBase.Tests.TestUtils;

namespace CryptoBase.Tests.Signatures.Rsa.Arithmetic;

// Kernels may lay out their scratch by its address, as MontgomeryKernelAdvSimd and MontgomeryPairKernelAdvSimd do to keep their operands within a page: wherever the scratch lies across a page boundary, and whatever it holds, the products and squares are right and nothing outside the scratch changes.
public class KernelScratchTest
{
	private const ulong Canary = 0xA5A5_5A5A_C3C3_3C3CUL;

	[Test]
	[MethodDataSource(typeof(MontgomeryKernelCase), nameof(MontgomeryKernelCase.All))]
	public async Task ProductsDoNotDependOnWhereTheScratchLies(MontgomeryKernelCase kernel)
	{
		SkipUnlessSupported(kernel);

		List<string> failures = [];
		Random random = new(61);
		int pageWords = Environment.SystemPageSize / sizeof(ulong);

		// The fewest limbs that the kernel holds and the most for which the dispatch takes it.
		foreach (int limbs in ((int[])[kernel.LimbCountsToTest[0], kernel.LimbCountsToTest[^1]]).Distinct())
		{
			BigInteger n = RandomBits(random, 64 * limbs) | BigInteger.One << 64 * limbs - 1 | 1;
			using MontgomeryContext context = kernel.Create(ToLimbs(n, limbs));
			int digits = context.DigitCount;
			int length = kernel.GetScratchLength(digits);
			BigInteger r = BigInteger.One << kernel.DigitBits * digits;
			BigInteger rInverse = ModInverse(r % n, n);
			BigInteger x = RandomBelow(random, 2 * n);
			BigInteger y = RandomBelow(random, 2 * n);
			BigInteger product = x * y * rInverse % n;
			BigInteger square = x * x * rInverse % n;
			ulong[] modulus = ToLimbs(n, digits, kernel.DigitBits);
			ulong[] left = ToLimbs(x, digits, kernel.DigitBits);
			ulong[] right = ToLimbs(y, digits, kernel.DigitBits);
			ulong[] result = new ulong[digits];
			// Room for the scratch to slide over a page boundary, with words before and after it.
			ulong[] arena = GC.AllocateArray<ulong>(2 * length + 2 * pageWords + 16, true);
			int boundary = PageBoundary(arena, length + 8, pageWords);
			// Every offset across the boundary for scratches shorter than 128 words, and about 64 offsets for longer ones.
			int step = Math.Max(1, length / 64);

			for (int offset = boundary - length - 4; offset <= boundary + 4; offset += step)
			{
				Span<ulong> scratch = arena.AsSpan(offset, length);
				arena.AsSpan().Fill(Canary);
				scratch.Fill(ulong.MaxValue);
				kernel.Multiply(modulus, result, left, right, scratch);
				Check(failures, kernel, result, product, n, $"{n:X}: {x:X}·{y:X} with the scratch at {offset - boundary}");
				scratch.Fill(ulong.MaxValue);
				kernel.Square(modulus, result, left, scratch);
				Check(failures, kernel, result, square, n, $"{n:X}: {x:X}² with the scratch at {offset - boundary}");

				if (arena.AsSpan(0, offset).ContainsAnyExcept(Canary) || arena.AsSpan(offset + length).ContainsAnyExcept(Canary))
				{
					failures.Add($"{n:X}: a write outside the scratch at {offset - boundary}");
				}
			}
		}

		await Assert.That(failures).IsEmpty();
	}

	// Moduli of as few digits as a kernel takes, down to one, which no context makes: the last blocks of a kernel may hold columns past the result, which it must not write. The words around the result stay as they were.
	[Test]
	[MethodDataSource(typeof(MontgomeryKernelCase), nameof(MontgomeryKernelCase.All))]
	public async Task FewDigitsStayWithinTheResult(MontgomeryKernelCase kernel)
	{
		SkipUnlessSupported(kernel);

		List<string> failures = [];
		Random random = new(63);
		int r = kernel.DigitBits;

		for (int digits = 1; digits <= Math.Min(8, kernel.MaxDigitCount); ++digits)
		{
			// Odd, with a nonzero top digit and R ≥ 4n.
			BigInteger low = digits is 1 ? 3 : BigInteger.One << r * (digits - 1);
			BigInteger n = low + RandomBelow(random, (BigInteger.One << r * digits - 2) - low) | 1;
			BigInteger rInverse = ModInverse((BigInteger.One << r * digits) % n, n);
			ulong[] modulus = ToLimbs(n, digits, r);
			ulong[] scratch = new ulong[kernel.GetScratchLength(digits)];

			for (int trial = 0; trial < 8; ++trial)
			{
				BigInteger x = RandomBelow(random, 2 * n);
				BigInteger y = RandomBelow(random, 2 * n);
				ulong[] left = ToLimbs(x, digits, r);
				ulong[] right = ToLimbs(y, digits, r);
				ulong[] arena = new ulong[digits + 16];
				Span<ulong> result = arena.AsSpan(8, digits);
				arena.AsSpan().Fill(Canary);
				kernel.Multiply(modulus, result, left, right, scratch);
				Check(failures, kernel, result, x * y * rInverse % n, n, $"{digits} digits: {x:X}·{y:X} mod {n:X}");

				if (arena.AsSpan(0, 8).ContainsAnyExcept(Canary) || arena.AsSpan(8 + digits).ContainsAnyExcept(Canary))
				{
					failures.Add($"{digits} digits: a product wrote outside the result");
				}

				arena.AsSpan().Fill(Canary);
				kernel.Square(modulus, result, left, scratch);
				Check(failures, kernel, result, x * x * rInverse % n, n, $"{digits} digits: {x:X}² mod {n:X}");

				if (arena.AsSpan(0, 8).ContainsAnyExcept(Canary) || arena.AsSpan(8 + digits).ContainsAnyExcept(Canary))
				{
					failures.Add($"{digits} digits: a square wrote outside the result");
				}
			}
		}

		await Assert.That(failures).IsEmpty();
	}

	[Test]
	[MethodDataSource(typeof(MontgomeryPairKernelCase), nameof(MontgomeryPairKernelCase.All))]
	public async Task PairProductsDoNotDependOnWhereTheScratchLies(MontgomeryPairKernelCase kernel)
	{
		SkipUnlessSupported(kernel);

		List<string> failures = [];
		Random random = new(62);
		int pageWords = Environment.SystemPageSize / sizeof(ulong);

		foreach (int limbs in (int[])[2, 16, 23, 32])
		{
			int digits = (64 * limbs + 2 + kernel.DigitBits - 1) / kernel.DigitBits;

			if (digits < kernel.MinDigitCount || digits > kernel.MaxDigitCount)
			{
				continue;
			}

			BigInteger p = RandomBits(random, 64 * limbs) | BigInteger.One << 64 * limbs - 1 | 1;
			BigInteger q = RandomBits(random, 64 * limbs) | BigInteger.One << 64 * limbs - 1 | 1;
			int length = kernel.GetScratchLength(digits);
			BigInteger r = BigInteger.One << kernel.DigitBits * digits;
			BigInteger pInverse = ModInverse(r % p, p);
			BigInteger qInverse = ModInverse(r % q, q);
			BigInteger x = RandomBelow(random, 2 * p);
			BigInteger y = RandomBelow(random, 2 * q);
			BigInteger u = RandomBelow(random, 2 * p);
			BigInteger v = RandomBelow(random, 2 * q);
			ulong[] first = ToLimbs(p, digits, kernel.DigitBits);
			ulong[] second = ToLimbs(q, digits, kernel.DigitBits);
			ulong[] left = Interleave(ToLimbs(x, digits, kernel.DigitBits), ToLimbs(y, digits, kernel.DigitBits));
			ulong[] right = Interleave(ToLimbs(u, digits, kernel.DigitBits), ToLimbs(v, digits, kernel.DigitBits));
			ulong[] result = new ulong[2 * digits];
			ulong[] arena = GC.AllocateArray<ulong>(2 * length + 2 * pageWords + 16, true);
			int boundary = PageBoundary(arena, length + 8, pageWords);
			int step = Math.Max(1, length / 256);

			for (int offset = boundary - length - 4; offset <= boundary + 4; offset += step)
			{
				Span<ulong> scratch = arena.AsSpan(offset, length);
				arena.AsSpan().Fill(Canary);
				scratch.Fill(ulong.MaxValue);
				kernel.Multiply(first, second, result, left, right, scratch);
				CheckPair(failures, kernel, result, x * u * pInverse % p, p, y * v * qInverse % q, q, $"{p:X}, {q:X}: ({x:X}, {y:X})·({u:X}, {v:X}) with the scratch at {offset - boundary}");
				scratch.Fill(ulong.MaxValue);
				kernel.Square(first, second, result, left, scratch);
				CheckPair(failures, kernel, result, x * x * pInverse % p, p, y * y * qInverse % q, q, $"{p:X}, {q:X}: ({x:X}, {y:X})² with the scratch at {offset - boundary}");

				if (arena.AsSpan(0, offset).ContainsAnyExcept(Canary) || arena.AsSpan(offset + length).ContainsAnyExcept(Canary))
				{
					failures.Add($"{p:X}, {q:X}: a write outside the scratch at {offset - boundary}");
				}
			}
		}

		await Assert.That(failures).IsEmpty();
	}

	// The index of the first word of the array on a page boundary from index start on.
	private static unsafe int PageBoundary(ulong[] pinned, int start, int pageWords)
	{
		nuint address = (nuint)Unsafe.AsPointer(ref pinned[start]);
		nuint page = (nuint)(pageWords * sizeof(ulong));
		nuint boundary = address + page - 1 & ~(page - 1);
		return start + (int)((boundary - address) / sizeof(ulong));
	}

	private static void Check(List<string> failures, MontgomeryKernelCase kernel, ReadOnlySpan<ulong> element, BigInteger expected, BigInteger n, string description)
	{
		BigInteger value = ToBigInteger(element, kernel.DigitBits);

		if (element.ContainsAnyExceptInRange(0UL, (1UL << kernel.DigitBits) - 1) || value >= 2 * n || value % n != expected)
		{
			failures.Add(description);
		}
	}

	// Both halves of a pair, each as Check takes one element.
	private static void CheckPair(List<string> failures, MontgomeryPairKernelCase kernel, ReadOnlySpan<ulong> pair, BigInteger firstExpected, BigInteger p, BigInteger secondExpected, BigInteger q, string description)
	{
		ulong[] first = new ulong[pair.Length / 2];
		ulong[] second = new ulong[pair.Length / 2];

		for (int i = 0; i < first.Length; ++i)
		{
			first[i] = pair[2 * i];
			second[i] = pair[2 * i + 1];
		}

		BigInteger x = ToBigInteger(first, kernel.DigitBits);
		BigInteger y = ToBigInteger(second, kernel.DigitBits);

		if (pair.ContainsAnyExceptInRange(0UL, (1UL << kernel.DigitBits) - 1) || x >= 2 * p || x % p != firstExpected || y >= 2 * q || y % q != secondExpected)
		{
			failures.Add(description);
		}
	}

	private static ulong[] Interleave(ulong[] first, ulong[] second)
	{
		ulong[] pair = new ulong[2 * first.Length];

		for (int i = 0; i < first.Length; ++i)
		{
			pair[2 * i] = first[i];
			pair[2 * i + 1] = second[i];
		}

		return pair;
	}
}
