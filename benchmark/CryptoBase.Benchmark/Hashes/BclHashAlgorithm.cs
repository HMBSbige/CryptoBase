using DotNetMD5 = System.Security.Cryptography.MD5;
using DotNetSha1 = System.Security.Cryptography.SHA1;
using DotNetSha256 = System.Security.Cryptography.SHA256;
using DotNetSha3_256 = System.Security.Cryptography.SHA3_256;
using DotNetSha3_384 = System.Security.Cryptography.SHA3_384;
using DotNetSha3_512 = System.Security.Cryptography.SHA3_512;
using DotNetSha384 = System.Security.Cryptography.SHA384;
using DotNetSha512 = System.Security.Cryptography.SHA512;

namespace CryptoBase.Benchmark.Hashes;

public interface IBclHashAlgorithm
{
	// SHA-3 depends on the platform's cryptographic library, which on macOS lacks it.
	static virtual bool IsSupported => true;

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

public readonly struct BclSha3_256 : IBclHashAlgorithm
{
	public static bool IsSupported => DotNetSha3_256.IsSupported;

	public static int HashData(ReadOnlySpan<byte> source, Span<byte> destination)
	{
		return DotNetSha3_256.HashData(source, destination);
	}
}

public readonly struct BclSha3_384 : IBclHashAlgorithm
{
	public static bool IsSupported => DotNetSha3_384.IsSupported;

	public static int HashData(ReadOnlySpan<byte> source, Span<byte> destination)
	{
		return DotNetSha3_384.HashData(source, destination);
	}
}

public readonly struct BclSha3_512 : IBclHashAlgorithm
{
	public static bool IsSupported => DotNetSha3_512.IsSupported;

	public static int HashData(ReadOnlySpan<byte> source, Span<byte> destination)
	{
		return DotNetSha3_512.HashData(source, destination);
	}
}
