using CryptoBase.Internal;
using static CryptoBase.Tests.TestUtils;

namespace CryptoBase.Tests;

public class FixedTimeTest
{
	// Lengths past two 512-bit vectors cover every path and tail; the longer ones are ML-KEM ciphertext lengths.
	[Test]
	public async Task EqualsFindsEveryFlippedBit()
	{
		List<string> failures = [];

		foreach (int length in Enumerable.Range(0, 144).Concat([768, 1088, 1568]))
		{
			byte[] left = CreateDeterministicSource(length);
			byte[] right = (byte[])left.Clone();

			if (!FixedTime.Equals(left, right))
			{
				failures.Add($"{length} bytes, equal");
			}

			for (int bit = 0; bit < 8 * length; ++bit)
			{
				right[bit / 8] ^= (byte)(1 << bit % 8);

				if (FixedTime.Equals(left, right))
				{
					failures.Add($"{length} bytes, bit {bit}");
				}

				right[bit / 8] ^= (byte)(1 << bit % 8);
			}
		}

		await Assert.That(failures).IsEmpty();
	}
}
