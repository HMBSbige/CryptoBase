namespace CryptoBase.Benchmark.Hashes.Sha3;

public readonly struct BclShake128 : IBclXof
{
	public static bool IsSupported => System.Security.Cryptography.Shake128.IsSupported;

	public static void HashData(ReadOnlySpan<byte> source, Span<byte> destination)
	{
		System.Security.Cryptography.Shake128.HashData(source, destination);
	}
}

public readonly struct BclShake256 : IBclXof
{
	public static bool IsSupported => System.Security.Cryptography.Shake256.IsSupported;

	public static void HashData(ReadOnlySpan<byte> source, Span<byte> destination)
	{
		System.Security.Cryptography.Shake256.HashData(source, destination);
	}
}
