using CryptoBase.Signatures.Rsa.Arithmetic;

namespace CryptoBase.Signatures.Rsa;

// An RSA public key and RSAVP1 (RFC 8017, Sec. 5.2.2). Immutable; calls may be concurrent.
internal sealed class RsaPublicOperation
{
	internal const int MinModulusBits = 512;
	internal const int MaxModulusBits = 16384;
	internal const int MaxPublicExponentBits = 33;

	private readonly ulong _exponent;

	// R^e mod n, as the digits of an element: the e-th power of x taken as an element is x^e·R^(1−e) in plain form, which a product with these digits brings to x^e, so that the input needs no conversion into Montgomery form.
	private readonly ulong[] _correction;

	private RsaPublicOperation(MontgomeryContext modulus, ulong exponent, int modulusBits, int exponentLength)
	{
		Context = modulus;
		_exponent = exponent;
		ModulusBits = modulusBits;
		ExponentLength = exponentLength;

		// The element of R² mod n stands for R, and its power e − 1 for R^(e−1), whose digits are R^e.
		ulong[] rSquared = new ulong[modulus.LimbCount];
		modulus.WriteRSquared(rSquared);
		_correction = new ulong[modulus.DigitCount];
		modulus.ToDigits(rSquared, _correction);
		modulus.ExponentiateVariableTime(_correction, exponent - 1, _correction);
		modulus.Reduce(_correction);
	}

	internal int ModulusBits { get; }

	// The context of n, which RsaPrivateOperation shares.
	internal MontgomeryContext Context { get; }

	// k = ⌈ModulusBits/8⌉.
	internal int ModulusLength => (ModulusBits + 7) / 8;

	// The length of e without leading zeros.
	internal int ExponentLength { get; }

	// modulus and exponent are unsigned big-endian and may have leading zero bytes.
	// ArgumentException: either is empty or zero, the modulus is even, or the exponent is even or below 3.
	// NotSupportedException: the modulus has fewer than 512 or more than 16384 bits, or the exponent more than 33 bits.
	internal static RsaPublicOperation Create(ReadOnlySpan<byte> modulus, ReadOnlySpan<byte> exponent)
	{
		modulus = TrimLeadingZeros(modulus);
		exponent = TrimLeadingZeros(exponent);

		// RFC 8017, Sec. 3.1: n is a product of odd primes, and e is odd, since it is coprime to λ(n), and at least 3.
		if (modulus.IsEmpty || (modulus[^1] & 1) is 0)
		{
			throw new ArgumentException("The RSA modulus is invalid.", nameof(modulus));
		}

		if (exponent.IsEmpty || (exponent[^1] & 1) is 0 || exponent is [1])
		{
			throw new ArgumentException("The RSA public exponent is invalid.", nameof(exponent));
		}

		// The lengths in bytes come first, so that the bit lengths of longer values are never computed.
		int modulusBits = modulus.Length <= (MaxModulusBits + 7) / 8 ? GetBitLength(modulus) : int.MaxValue;

		if (modulusBits is < MinModulusBits or > MaxModulusBits || exponent.Length > (MaxPublicExponentBits + 7) / 8 || GetBitLength(exponent) > MaxPublicExponentBits)
		{
			throw new NotSupportedException("The RSA modulus must have 512 to 16384 bits, and the public exponent at most 33 bits.");
		}

		Span<ulong> limbs = stackalloc ulong[(modulus.Length + sizeof(ulong) - 1) / sizeof(ulong)];
		Limbs.FromBigEndian(modulus, limbs);
		ulong value = 0;

		foreach (byte b in exponent)
		{
			value = value << 8 | b;
		}

		return new RsaPublicOperation(MontgomeryKernelDispatch.Create(limbs, secret: false), value, modulusBits, exponent.Length);
	}

	// destination is exactly ModulusLength bytes.
	internal void WriteModulus(Span<byte> destination)
	{
		ArgumentOutOfRangeException.ThrowIfNotEqual(destination.Length, ModulusLength, nameof(destination));

		Limbs.ToBigEndian(Context.Modulus, destination);
	}

	// destination is exactly ExponentLength bytes.
	internal void WriteExponent(Span<byte> destination)
	{
		ArgumentOutOfRangeException.ThrowIfNotEqual(destination.Length, ExponentLength, nameof(destination));

		ulong value = _exponent;

		for (int i = destination.Length - 1; i >= 0; --i)
		{
			destination[i] = (byte)value;
			value >>= 8;
		}
	}

	// RSAVP1: input and output are ModulusLength bytes, big-endian; they may be the same span, but must not overlap partially.
	// Returns false, leaving output unchanged, if input >= n; otherwise writes input^e mod n. The time depends on e alone: nothing branches on or indexes by the input, so that the private key may run this on a secret.
	internal bool TryApply(ReadOnlySpan<byte> input, Span<byte> output)
	{
		ArgumentOutOfRangeException.ThrowIfNotEqual(input.Length, ModulusLength, nameof(input));
		ArgumentOutOfRangeException.ThrowIfNotEqual(output.Length, ModulusLength, nameof(output));

		CipherBufferGuard.SourceDestinationOverlap(input, output, nameof(output));

		MontgomeryContext modulus = Context;
		int limbs = modulus.LimbCount;
		int digits = modulus.DigitCount;
		int bufferLength = limbs + digits;
		using CryptoBuffer<ulong> buffer = CryptoBuffer<ulong>.ShouldUsePool(bufferLength) ? new CryptoBuffer<ulong>(bufferLength) : new CryptoBuffer<ulong>(stackalloc ulong[bufferLength]);
		Span<ulong> value = buffer.Span.Slice(0, limbs);
		Span<ulong> element = buffer.Span.Slice(limbs, digits);
		Limbs.FromBigEndian(input, value);

		if (Limbs.LessThan(value, modulus.Modulus) is 0)
		{
			return false;
		}

		modulus.ToDigits(value, element);
		modulus.ExponentiateVariableTime(element, _exponent, element);
		modulus.Multiply(element, element, _correction);
		modulus.FromDigits(element, value);
		Limbs.ToBigEndian(value, output);
		return true;
	}

	private static ReadOnlySpan<byte> TrimLeadingZeros(ReadOnlySpan<byte> value)
	{
		int start = value.IndexOfAnyExcept((byte)0);
		return start < 0 ? default : value.Slice(start);
	}

	// Of a value without leading zeros.
	private static int GetBitLength(ReadOnlySpan<byte> value)
	{
		return 8 * value.Length - BitOperations.LeadingZeroCount(value[0]) + 24;
	}
}
