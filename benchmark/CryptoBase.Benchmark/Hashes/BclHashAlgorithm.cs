using DotNetMD5 = System.Security.Cryptography.MD5;
using DotNetSha1 = System.Security.Cryptography.SHA1;
using DotNetSha256 = System.Security.Cryptography.SHA256;
using DotNetSha384 = System.Security.Cryptography.SHA384;
using DotNetSha512 = System.Security.Cryptography.SHA512;

namespace CryptoBase.Benchmark.Hashes;

public interface IBclHashAlgorithm
{
	static abstract int HashData(ReadOnlySpan<byte> source, Span<byte> destination);
}

public readonly struct BclMD5 : IBclHashAlgorithm
{
	public static int HashData(ReadOnlySpan<byte> source, Span<byte> destination)
	{
		return DotNetMD5.HashData(source, destination);
	}
}

public readonly struct BclSha1 : IBclHashAlgorithm
{
	public static int HashData(ReadOnlySpan<byte> source, Span<byte> destination)
	{
		return DotNetSha1.HashData(source, destination);
	}
}

public readonly struct BclSha256 : IBclHashAlgorithm
{
	public static int HashData(ReadOnlySpan<byte> source, Span<byte> destination)
	{
		return DotNetSha256.HashData(source, destination);
	}
}

public readonly struct BclSha384 : IBclHashAlgorithm
{
	public static int HashData(ReadOnlySpan<byte> source, Span<byte> destination)
	{
		return DotNetSha384.HashData(source, destination);
	}
}

public readonly struct BclSha512 : IBclHashAlgorithm
{
	public static int HashData(ReadOnlySpan<byte> source, Span<byte> destination)
	{
		return DotNetSha512.HashData(source, destination);
	}
}
