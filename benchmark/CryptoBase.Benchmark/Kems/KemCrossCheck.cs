namespace CryptoBase.Benchmark.Kems;

internal static class KemCrossCheck
{
	/// <summary>Decapsulates the ciphertext of every encapsulator with every decapsulator, leaving the last ciphertext for the decapsulation benchmarks.</summary>
	public static void Run(byte[] sharedSecret, IReadOnlyList<Action> encapsulators, IReadOnlyList<Action> decapsulators)
	{
		byte[] expected = new byte[sharedSecret.Length];

		foreach (Action encapsulate in encapsulators)
		{
			encapsulate();
			sharedSecret.CopyTo(expected);

			foreach (Action decapsulate in decapsulators)
			{
				sharedSecret.AsSpan().Clear();
				decapsulate();

				if (!sharedSecret.AsSpan().SequenceEqual(expected))
				{
					throw new InvalidOperationException("Benchmark implementations produced different shared secrets.");
				}
			}
		}
	}
}
