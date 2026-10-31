using CryptoBase.Macs.Hmac;

namespace CryptoBase.Otp;

// HOTP (RFC 4226) under one key. After Initialize nothing changes it until ZeroMemory, so concurrent calls are safe.
internal struct OtpKey<TCore> where TCore : unmanaged, IHmacHashCore<TCore>
{
	// Dynamic truncation reads 4 bytes at an offset of up to 15.
	private const int MinMacLength = 20;

	private HmacState<TCore> _hmac;

	internal static void ThrowIfInvalid(ReadOnlySpan<byte> key, string paramName)
	{
		if (TCore.HashLength < MinMacLength)
		{
			throw new NotSupportedException($"HOTP needs an HMAC of at least {MinMacLength} bytes, but {typeof(TCore).Name} produces {TCore.HashLength}.");
		}

		if (key.IsEmpty)
		{
			throw new ArgumentException("The key must not be empty.", paramName);
		}
	}

	internal void Initialize(ReadOnlySpan<byte> key)
	{
		_hmac.Initialize(key, true);
	}

	internal readonly void Generate(ulong counter, OtpCodeFormat format, Span<char> destination)
	{
		format.Write(Truncate(counter), destination);
	}

	// Computes every counter from first to last, so the time does not reveal which one matched; the first match is returned.
	[SkipLocalsInit]
	internal readonly bool Verify(ulong first, ulong last, OtpCodeFormat format, ReadOnlySpan<char> code, out ulong matched)
	{
		Debug.Assert(first <= last);
		matched = 0;

		if (code.Length != format.Length)
		{
			return false;
		}

		using CryptoBuffer<char> expectedBuffer = new(stackalloc char[format.Length]);
		Span<char> expected = expectedBuffer.Span;
		ReadOnlySpan<byte> codeBytes = MemoryMarshal.AsBytes(code);
		bool found = false;

		for (ulong counter = first; ; ++counter)
		{
			Generate(counter, format, expected);
			bool equal = FixedTime.Equals(MemoryMarshal.AsBytes(expected), codeBytes);

			// Branch-free: keep the first match.
			ulong select = 0UL - Unsafe.BitCast<bool, byte>(equal & !found);
			matched = matched & ~select | counter & select;
			found |= equal;

			if (counter == last)
			{
				return found;
			}
		}
	}

	internal void ZeroMemory()
	{
		_hmac.ZeroMemory();
	}

	// The 31-bit integer of RFC 4226 section 5.3, with the offset taken from the last byte as RFC 6238 does for longer HMACs.
	[SkipLocalsInit]
	private readonly uint Truncate(ulong counter)
	{
		Span<byte> message = stackalloc byte[sizeof(ulong)];
		BinaryPrimitives.WriteUInt64BigEndian(message, counter);

		using CryptoBuffer<byte> macBuffer = new(stackalloc byte[TCore.HashLength]);
		Span<byte> mac = macBuffer.Span;
		_hmac.MacFromSeeds(message, mac);

		int offset = mac[^1] & 0xF;
		return BinaryPrimitives.ReadUInt32BigEndian(mac.Slice(offset)) & 0x7FFF_FFFF;
	}
}
