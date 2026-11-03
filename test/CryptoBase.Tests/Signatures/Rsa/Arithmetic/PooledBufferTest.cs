using CryptoBase.Signatures.Rsa;
using CryptoBase.Signatures.Rsa.Arithmetic;
using System.Buffers;
using System.Numerics;
using System.Security.Cryptography;
using static CryptoBase.Tests.Signatures.Rsa.Arithmetic.RsaArithmeticTestUtils;

namespace CryptoBase.Tests.Signatures.Rsa.Arithmetic;

// CryptoBuffer rents from the shared pools, whose arrays may hold anything that other code left in them. With every pooled array filled with ones before each operation, a result that relies on zeroed storage comes out wrong. The test runs alone, so that no other test receives those arrays meanwhile.
[NotInParallel]
public class PooledBufferTest
{
	[Test]
	public async Task OperationsDoNotRelyOnZeroedBuffers()
	{
		List<string> failures = [];
		Random random = new(51);

		try
		{
			foreach (int limbs in (ReadOnlySpan<int>)[16, 33, 256])
			{
				BigInteger n = RandomBits(random, 64 * limbs) | BigInteger.One << 64 * limbs - 1 | 1;
				BigInteger x = RandomBelow(random, n);
				Poison();
				using MontgomeryContext context = MontgomeryKernelDispatch.Create(ToLimbs(n, limbs));
				ulong[] element = new ulong[context.DigitCount];
				ulong[] result = new ulong[limbs];
				Poison();
				context.ToMontgomery(ToLimbs(x, limbs), element);
				Poison();
				context.ExponentiateVariableTime(element, 65537, element);
				Poison();
				context.FromMontgomery(element, result);

				if (ToBigInteger(result) != BigInteger.ModPow(x, 65537, n))
				{
					failures.Add($"{limbs} limbs");
				}
			}

			BigInteger large = RandomBits(random, 16384) | BigInteger.One << 16383 | 1;
			Poison();
			RsaPublicOperation publicKey = RsaPublicOperation.Create(ToBigEndian(large, 2048), [3]);
			byte[] output = new byte[2048];
			Poison();

			if (!publicKey.TryApply(ToBigEndian(BigInteger.One, 2048), output) || !FromBigEndian(output).IsOne)
			{
				failures.Add("1^3 mod a 16384-bit modulus");
			}

			using RSA rsa = RSA.Create(4096);
			RSAParameters parameters = rsa.ExportParameters(true);
			Poison();
			using RsaPrivateOperation key = RsaPrivateOperation.Create(RsaPublicOperation.Create(parameters.Modulus, parameters.Exponent), parameters.D, parameters.P, parameters.Q, parameters.DP, parameters.DQ, parameters.InverseQ);
			BigInteger modulus = FromBigEndian(parameters.Modulus);
			BigInteger message = RandomBelow(random, modulus);
			byte[] signature = new byte[512];
			Poison();
			key.Apply(ToBigEndian(message, 512), signature);

			if (FromBigEndian(signature) != BigInteger.ModPow(message, FromBigEndian(parameters.D), modulus))
			{
				failures.Add("Apply with a 4096-bit key");
			}

			Poison();
			using RsaPrivateOperation generated = RsaPrivateOperation.Generate(4096, 65537);
			BigInteger p = Read(generated, RsaPrivateComponent.Prime1);
			BigInteger q = Read(generated, RsaPrivateComponent.Prime2);
			BigInteger d = Read(generated, RsaPrivateComponent.PrivateExponent);

			if (Read(generated, RsaPrivateComponent.Exponent1) != d % (p - 1) || Read(generated, RsaPrivateComponent.Exponent2) != d % (q - 1) || !(q * Read(generated, RsaPrivateComponent.Coefficient) % p).IsOne || BigInteger.Abs(p - q) <= BigInteger.One << 1948)
			{
				failures.Add("Generate(4096)");
			}
		}
		finally
		{
			Clean();
		}

		await Assert.That(failures).IsEmpty();
	}

	private static BigInteger Read(RsaPrivateOperation key, RsaPrivateComponent component)
	{
		byte[] value = new byte[key.GetLength(component)];
		key.Write(component, value);
		return FromBigEndian(value);
	}

	// Every bucket from 32 to 32768 elements, several arrays deep.
	private static void Poison()
	{
		Fill(ArrayPool<ulong>.Shared, ulong.MaxValue);
		Fill(ArrayPool<long>.Shared, -1);
	}

	private static void Clean()
	{
		Fill(ArrayPool<ulong>.Shared, 0UL);
		Fill(ArrayPool<long>.Shared, 0L);
	}

	private static void Fill<T>(ArrayPool<T> pool, T value)
	{
		for (int length = 32; length <= 32768; length *= 2)
		{
			T[][] arrays = new T[16][];

			for (int i = 0; i < arrays.Length; ++i)
			{
				arrays[i] = pool.Rent(length);
				arrays[i].AsSpan().Fill(value);
			}

			foreach (T[] array in arrays)
			{
				pool.Return(array);
			}
		}
	}
}
