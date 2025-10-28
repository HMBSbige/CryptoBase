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
		ArgumentOutOfRangeException.ThrowIfLessThan(prk.Length, hashLength, nameof(prk));

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

		ArgumentOutOfRangeException.ThrowIfZero(output.Length, nameof(output));

		ArgumentOutOfRangeException.ThrowIfLessThan(prk.Length, hashLength, nameof(prk));

		int maxOkmLength = 255 * hashLength;
		ArgumentOutOfRangeException.ThrowIfGreaterThan(output.Length, maxOkmLength, nameof(output));

		ExpandInternal(type, hashLength, prk, output, info);
	}

	private static void ExpandInternal(DigestType type, int hashLength, ReadOnlySpan<byte> prk, Span<byte> output, ReadOnlySpan<byte> info)
	{
		byte counter = 0;
		Span<byte> counterSpan = new(ref counter);
		Span<byte> t = Span<byte>.Empty;
		Span<byte> remainingOutput = output;

		const int maxStackInfoBuffer = 64;
		Span<byte> tempInfoBuffer = stackalloc byte[maxStackInfoBuffer];
		scoped ReadOnlySpan<byte> infoBuffer;
		byte[]? rentedTempInfoBuffer = null;

		if (output.Overlaps(info))
		{
			if (info.Length > maxStackInfoBuffer)
			{
				rentedTempInfoBuffer = ArrayPool<byte>.Shared.Rent(info.Length);
				tempInfoBuffer = rentedTempInfoBuffer;
			}

			tempInfoBuffer = tempInfoBuffer.Slice(0, info.Length);
			info.CopyTo(tempInfoBuffer);
			infoBuffer = tempInfoBuffer;
		}
		else
		{
			infoBuffer = info;
		}

		using (IMac hmac = HmacUtils.Create(type, prk))
		{
			for (int i = 1; ; ++i)
			{
				hmac.Update(t);
				hmac.Update(infoBuffer);
				counter = (byte)i;
				hmac.Update(counterSpan);

				if (remainingOutput.Length >= hashLength)
				{
					t = remainingOutput.Slice(0, hashLength);
					remainingOutput = remainingOutput.Slice(hashLength);
					hmac.GetMac(t);
				}
				else
				{
					if (remainingOutput.Length > 0)
					{
						Span<byte> lastChunk = stackalloc byte[hashLength];
						hmac.GetMac(lastChunk);
						lastChunk.Slice(0, remainingOutput.Length).CopyTo(remainingOutput);
					}

					break;
				}
			}
		}

		if (rentedTempInfoBuffer is not null)
		{
			CryptographicOperations.ZeroMemory(rentedTempInfoBuffer.AsSpan(0, info.Length));
			ArrayPool<byte>.Shared.Return(rentedTempInfoBuffer);
		}
	}

	public static void DeriveKey(DigestType type, ReadOnlySpan<byte> ikm, Span<byte> output, ReadOnlySpan<byte> salt, ReadOnlySpan<byte> info)
	{
		int hashLength = HashLength(type);

		ArgumentOutOfRangeException.ThrowIfZero(output.Length, nameof(output));

		int maxOkmLength = 255 * hashLength;
		ArgumentOutOfRangeException.ThrowIfGreaterThan(output.Length, maxOkmLength, nameof(output));

		DeriveKeyInternal(type, hashLength, ikm, output, salt, info);
	}

	private static void DeriveKeyInternal(DigestType type, int hashLength, ReadOnlySpan<byte> ikm, Span<byte> output, ReadOnlySpan<byte> salt, ReadOnlySpan<byte> info)
	{
		using CryptoBuffer<byte> buffer = new(stackalloc byte[hashLength]);
		Span<byte> prk = buffer.Span;

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
			_ => throw new ArgumentOutOfRangeException(nameof(type), type, default)
		};
	}
}
