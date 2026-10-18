using System.Globalization;

namespace CryptoBase.Kdf.Argon2;

// The PHC string format of the reference implementation, $argon2<type>$v=19$m=<m>,t=<t>,p=<p>$<salt>$<hash>, with the salt and hash in standard Base64 without padding.
internal readonly ref struct Argon2PhcString
{
	internal const int MinSaltLength = 8;

	private const int MaxPrefixLength = 52; // $argon2id$v=19$m=<10 digits>,t=<10 digits>,p=<8 digits>$

	private Argon2PhcString(Argon2Type type, Argon2Parameters parameters, ReadOnlySpan<char> salt, ReadOnlySpan<char> hash)
	{
		Type = type;
		Parameters = parameters;
		EncodedSalt = salt;
		EncodedHash = hash;
	}

	internal Argon2Type Type { get; }

	internal Argon2Parameters Parameters { get; }

	internal int SaltLength => DecodedLength(EncodedSalt.Length);

	internal int HashLength => DecodedLength(EncodedHash.Length);

	private ReadOnlySpan<char> EncodedSalt { get; }

	private ReadOnlySpan<char> EncodedHash { get; }

	internal static Argon2PhcString Parse(ReadOnlySpan<char> encoded)
	{
		ReadOnlySpan<char> rest = encoded;
		Consume(ref rest, "$");

		int typeEnd = rest.IndexOf('$');

		if (typeEnd < 0)
		{
			throw InvalidString();
		}

		Argon2Type type = rest.Slice(0, typeEnd) switch
		{
			"argon2d" => Argon2Type.Argon2d,
			"argon2i" => Argon2Type.Argon2i,
			"argon2id" => Argon2Type.Argon2id,
			_ => throw new FormatException("The string does not name Argon2d, Argon2i or Argon2id.")
		};
		rest = rest.Slice(typeEnd);

		Consume(ref rest, "$v=");

		if (ReadDecimal(ref rest) is not (int)Argon2Core.Version)
		{
			throw new FormatException("Only version 19 of Argon2 is supported.");
		}

		Consume(ref rest, "$m=");
		int memorySizeInKibibytes = ReadDecimal(ref rest);
		Consume(ref rest, ",t=");
		int iterations = ReadDecimal(ref rest);
		Consume(ref rest, ",p=");
		int parallelism = ReadDecimal(ref rest);
		Consume(ref rest, "$");

		if (parallelism is < 1 or > Argon2Parameters.MaxParallelism || iterations < 1 || memorySizeInKibibytes < 8 * parallelism)
		{
			throw new FormatException("The Argon2 parameters are out of range.");
		}

		int saltEnd = rest.IndexOf('$');

		if (saltEnd < 0)
		{
			throw InvalidString();
		}

		ReadOnlySpan<char> salt = rest.Slice(0, saltEnd);
		ReadOnlySpan<char> hash = rest.Slice(saltEnd + 1);

		if (!IsValidBase64(salt) || !IsValidBase64(hash))
		{
			throw new FormatException("The salt and the hash must be Base64 without padding.");
		}

		if (DecodedLength(salt.Length) < MinSaltLength || DecodedLength(hash.Length) < Argon2Core.MinTagLength)
		{
			throw new FormatException("The salt must be at least 8 bytes long, and the hash at least 4 bytes long.");
		}

		return new Argon2PhcString(type, new Argon2Parameters(memorySizeInKibibytes, iterations, parallelism), salt, hash);
	}

	internal void DecodeSalt(Span<byte> destination)
	{
		DecodeBase64(EncodedSalt, destination);
	}

	internal void DecodeHash(Span<byte> destination)
	{
		DecodeBase64(EncodedHash, destination);
	}

	internal static string Format(Argon2Type type, Argon2Parameters parameters, ReadOnlySpan<byte> salt, ReadOnlySpan<byte> hash)
	{
		Span<char> prefix = stackalloc char[MaxPrefixLength];
		bool formatted = prefix.TryWrite(CultureInfo.InvariantCulture, $"${TypeName(type)}$v={Argon2Core.Version}$m={parameters.MemorySizeInKibibytes},t={parameters.Iterations},p={parameters.Parallelism}$", out int prefixLength);
		Debug.Assert(formatted);

		long length = prefixLength + EncodedLength(salt.Length) + 1 + EncodedLength(hash.Length);

		if (length > Array.MaxLength)
		{
			throw new OutOfMemoryException();
		}

		return string.Create((int)length, new FormatState(prefix.Slice(0, prefixLength), salt, hash), static (destination, state) => state.WriteTo(destination));
	}

	private static string TypeName(Argon2Type type)
	{
		return type switch
		{
			Argon2Type.Argon2d => "argon2d",
			Argon2Type.Argon2i => "argon2i",
			_ => "argon2id"
		};
	}

	private static void Consume(ref ReadOnlySpan<char> rest, ReadOnlySpan<char> expected)
	{
		if (!rest.StartsWith(expected, StringComparison.Ordinal))
		{
			throw InvalidString();
		}

		rest = rest.Slice(expected.Length);
	}

	// Like the reference implementation, this accepts only digits without leading zeros.
	private static int ReadDecimal(ref ReadOnlySpan<char> rest)
	{
		int length = rest.IndexOfAnyExceptInRange('0', '9');

		if (length < 0)
		{
			length = rest.Length;
		}

		ReadOnlySpan<char> digits = rest.Slice(0, length);

		if (digits is [] or ['0', _, ..])
		{
			throw InvalidString();
		}

		if (!int.TryParse(digits, NumberStyles.None, CultureInfo.InvariantCulture, out int value))
		{
			throw new FormatException("The Argon2 parameters are out of range.");
		}

		rest = rest.Slice(length);
		return value;
	}

	private static FormatException InvalidString()
	{
		return new FormatException("The string is not an Argon2 PHC string.");
	}

	private static long EncodedLength(int byteCount)
	{
		int remainder = byteCount % 3;
		return byteCount / 3 * 4L + (remainder is 0 ? 0 : remainder + 1);
	}

	private static int DecodedLength(int charCount)
	{
		int remainder = charCount % 4;
		return charCount / 4 * 3 + (remainder is 0 ? 0 : remainder - 1);
	}

	// Like the reference implementation, this rejects nonzero bits past the last whole byte, so that each byte string has a single encoding.
	private static bool IsValidBase64(ReadOnlySpan<char> source)
	{
		if (source.Length % 4 is 1)
		{
			return false;
		}

		int invalid = 0;

		foreach (char c in source)
		{
			invalid |= DecodeSextet(c);
		}

		int unusedBitMask = (source.Length % 4) switch
		{
			2 => 0b1111,
			3 => 0b11,
			_ => 0
		};

		return invalid >= 0 && (source.IsEmpty || (DecodeSextet(source[^1]) & unusedBitMask) is 0);
	}

	private static void DecodeBase64(ReadOnlySpan<char> source, Span<byte> destination)
	{
		Debug.Assert(destination.Length == DecodedLength(source.Length));

		int accumulator = 0;
		int bitCount = 0;
		int written = 0;

		foreach (char c in source)
		{
			accumulator = accumulator << 6 | DecodeSextet(c);
			bitCount += 6;

			if (bitCount >= 8)
			{
				bitCount -= 8;
				destination[written++] = (byte)(accumulator >> bitCount);
			}
		}
	}

	private static void EncodeBase64(ReadOnlySpan<byte> source, Span<char> destination)
	{
		int accumulator = 0;
		int bitCount = 0;
		int written = 0;

		foreach (byte b in source)
		{
			accumulator = accumulator << 8 | b;
			bitCount += 8;

			while (bitCount >= 6)
			{
				bitCount -= 6;
				destination[written++] = EncodeSextet(accumulator >> bitCount & 0x3F);
			}
		}

		if (bitCount > 0)
		{
			destination[written] = EncodeSextet(accumulator << 6 - bitCount & 0x3F);
		}
	}

	// The hash is secret, so characters and sextets are converted with arithmetic rather than branches or table lookups.
	private static int DecodeSextet(int c)
	{
		return -1
			+ (InRange(c, 'A', 'Z') & c - 'A' + 1)
			+ (InRange(c, 'a', 'z') & c - 'a' + 27)
			+ (InRange(c, '0', '9') & c - '0' + 53)
			+ (InRange(c, '+', '+') & 63)
			+ (InRange(c, '/', '/') & 64);
	}

	private static char EncodeSextet(int sextet)
	{
		int c = sextet + 'A';
		c += InRange(sextet, 26, 51) & 'a' - 'A' - 26;
		c += InRange(sextet, 52, 61) & '0' - 'A' - 52;
		c += InRange(sextet, 62, 62) & '+' - 'A' - 62;
		c += InRange(sextet, 63, 63) & '/' - 'A' - 63;
		return (char)c;
	}

	// All bits are set if low <= value <= high, and none otherwise.
	private static int InRange(int value, int low, int high)
	{
		return (low - 1 - value & value - high - 1) >> 31;
	}

	private readonly ref struct FormatState(ReadOnlySpan<char> prefix, ReadOnlySpan<byte> salt, ReadOnlySpan<byte> hash)
	{
		private readonly ReadOnlySpan<char> _prefix = prefix;
		private readonly ReadOnlySpan<byte> _salt = salt;
		private readonly ReadOnlySpan<byte> _hash = hash;

		internal void WriteTo(Span<char> destination)
		{
			_prefix.CopyTo(destination);
			destination = destination.Slice(_prefix.Length);

			int saltLength = (int)EncodedLength(_salt.Length);
			EncodeBase64(_salt, destination.Slice(0, saltLength));
			destination[saltLength] = '$';
			EncodeBase64(_hash, destination.Slice(saltLength + 1));
		}
	}
}
