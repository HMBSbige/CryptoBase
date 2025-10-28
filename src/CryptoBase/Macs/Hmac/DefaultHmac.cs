using CryptoBase.Abstractions;

namespace CryptoBase.Macs.Hmac;

internal sealed class DefaultHmac : IMac
{
	public string Name { get; }

	public int Length => _hasher.HashLengthInBytes;

	private readonly IncrementalHash _hasher;

	public DefaultHmac(scoped ReadOnlySpan<byte> key, HashAlgorithmName name)
	{
		_hasher = IncrementalHash.CreateHMAC(name, key);
		Name = name.ToString() switch
		{
			@"MD5" => @"HMAC-MD5",
			@"SHA1" => @"HMAC-SHA-1",
			@"SHA256" => @"HMAC-SHA-256",
			@"SHA384" => @"HMAC-SHA-384",
			@"SHA512" => @"HMAC-SHA-512",
			_ => name.ToString()
		};
	}

	public void Update(scoped ReadOnlySpan<byte> source)
	{
		_hasher.AppendData(source);
	}

	public void GetMac(scoped Span<byte> destination)
	{
		_hasher.GetHashAndReset(destination);
	}

	public void Reset()
	{
		Span<byte> destination = stackalloc byte[Length];
		_hasher.GetHashAndReset(destination);
	}

	public void Dispose()
	{
		_hasher.Dispose();
	}
}
