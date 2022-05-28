using CryptoBase.Abstractions;
using CryptoBase.Digests;
using CryptoBase.Macs.Hmac;

namespace CryptoBase.KDF;

/// <summary>
/// https://datatracker.ietf.org/doc/html/rfc5869
/// </summary>
public static class Hkdf
{
	public static int Extract(DigestType type, ReadOnlySpan<byte> ikm, ReadOnlySpan<byte> salt, Span<byte> prk)
	{
		int hashLength = HashLength(type);
		if (prk.Length < hashLength)
		{
			throw new ArgumentException(@"prk too small", nameof(prk));
		}

		if (prk.Length > hashLength)
		{
			prk = prk[..hashLength];
		}

		ExtractInternal(type, ikm, salt, prk);

		return hashLength;
	}

	private static void ExtractInternal(DigestType type, ReadOnlySpan<byte> ikm, ReadOnlySpan<byte> salt, Span<byte> prk)
	{
		using IMac hmac = HmacUtils.Create(type, salt);

		hmac.Update(ikm);
		hmac.GetMac(prk);
	}

	public static void Expand(DigestType type, ReadOnlySpan<byte> prk, Span<byte> output, ReadOnlySpan<byte> info)
	{
		int hashLength = HashLength(type);

		if (output.IsEmpty)
		{
			throw new ArgumentException(@"Destination too short", nameof(output));
		}

		int maxOkmLength = 255 * hashLength;
		if (output.Length > maxOkmLength)
		{
			throw new ArgumentException(@"Okm too large", nameof(output));
		}

		ExpandInternal(type, hashLength, prk, output, info);
	}

	private static void ExpandInternal(DigestType type, int hashLength, ReadOnlySpan<byte> prk, Span<byte> output, ReadOnlySpan<byte> info)
	{
		if (prk.Length < hashLength)
		{
			throw new ArgumentException(@"prk too small", nameof(prk));
		}

		if (output.Overlaps(info))
		{
			throw new InvalidOperationException(@"the info input overlaps with the output destination");
		}

		Span<byte> counterSpan = stackalloc byte[1];
		ref byte counter = ref counterSpan[0];
		Span<byte> t = Span<byte>.Empty;
		Span<byte> remainingOutput = output;

		using IMac hmac = HmacUtils.Create(type, prk);
		for (int i = 1; ; ++i)
		{
			hmac.Update(t);
			hmac.Update(info);
			counter = (byte)i;
			hmac.Update(counterSpan);

			if (remainingOutput.Length >= hashLength)
			{
				t = remainingOutput[..hashLength];
				remainingOutput = remainingOutput[hashLength..];
				hmac.GetMac(t);
			}
			else
			{
				if (remainingOutput.Length > 0)
				{
					// ReSharper disable once StackAllocInsideLoop
					Span<byte> lastChunk = stackalloc byte[hashLength];
					hmac.GetMac(lastChunk);
					lastChunk[..remainingOutput.Length].CopyTo(remainingOutput);
				}

				break;
			}
		}
	}

	public static void DeriveKey(DigestType type, ReadOnlySpan<byte> ikm, Span<byte> output, ReadOnlySpan<byte> salt, ReadOnlySpan<byte> info)
	{
		int hashLength = HashLength(type);

		if (output.IsEmpty)
		{
			throw new ArgumentException(@"Destination too short", nameof(output));
		}

		int maxOkmLength = 255 * hashLength;
		if (output.Length > maxOkmLength)
		{
			throw new ArgumentException(@"Okm too large", nameof(output));
		}

		Span<byte> prk = stackalloc byte[hashLength];

		ExtractInternal(type, ikm, salt, prk);
		ExpandInternal(type, hashLength, prk, output, info);
	}

	private static int HashLength(DigestType type)
	{
		return type switch
		{
			DigestType.Sm3 => HashConstants.SM3Length,
			DigestType.Md5 => HashConstants.Md5Length,
			DigestType.Sha1 => HashConstants.Sha1Length,
			DigestType.Sha224 => HashConstants.Sha224Length,
			DigestType.Sha256 => HashConstants.Sha256Length,
			DigestType.Sha384 => HashConstants.Sha384Length,
			DigestType.Sha512 => HashConstants.Sha512Length,
			DigestType.Crc32 => HashConstants.Crc32Length,
			DigestType.Crc32C => HashConstants.Crc32Length,
			_ => throw new ArgumentOutOfRangeException(nameof(type))
		};
	}
}
