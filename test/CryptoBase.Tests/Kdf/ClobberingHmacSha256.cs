using CryptoBase.Abstractions.Macs;
using CryptoBase.Hashes.Sha256;
using CryptoBase.Macs.Hmac;

namespace CryptoBase.Tests.Kdf;

/// <summary>
/// HMAC-SHA256 that overwrites the destination before it reads the key and source or finishes the MAC, so that the generic KDF tests fail if a KDF hands
/// a MAC a destination that overlaps an input it still needs.
/// </summary>
internal sealed class ClobberingHmacSha256 : IMacAlgorithm<ClobberingHmacSha256>
{
	private const byte Sentinel = 0x5A;

	private readonly HmacAlgorithm<Sha256HashAlgorithm> _hmac;

	private ClobberingHmacSha256(HmacAlgorithm<Sha256HashAlgorithm> hmac)
	{
		_hmac = hmac;
	}

	public static int MacLength => HmacAlgorithm<Sha256HashAlgorithm>.MacLength;

	public static ClobberingHmacSha256 Create(ReadOnlySpan<byte> key)
	{
		return new ClobberingHmacSha256(HmacAlgorithm<Sha256HashAlgorithm>.Create(key));
	}

	public static int Mac(ReadOnlySpan<byte> key, ReadOnlySpan<byte> source, Span<byte> destination)
	{
		Clobber(destination);
		return HmacAlgorithm<Sha256HashAlgorithm>.Mac(key, source, destination);
	}

	public void Append(ReadOnlySpan<byte> source)
	{
		_hmac.Append(source);
	}

	public void Reset()
	{
		_hmac.Reset();
	}

	public int GetCurrentMac(Span<byte> destination)
	{
		Clobber(destination);
		return _hmac.GetCurrentMac(destination);
	}

	public int GetMacAndReset(Span<byte> destination)
	{
		Clobber(destination);
		return _hmac.GetMacAndReset(destination);
	}

	public void Dispose()
	{
		_hmac.Dispose();
	}

	private static void Clobber(Span<byte> destination)
	{
		ArgumentOutOfRangeException.ThrowIfLessThan(destination.Length, MacLength, nameof(destination));

		destination.Slice(0, MacLength).Fill(Sentinel);
	}
}
