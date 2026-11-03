using CryptoBase.Signatures.Rsa.Arithmetic;

namespace CryptoBase.Signatures.Rsa;

// An RSA private key and RSASP1 (RFC 8017, Sec. 5.2.1). Calls to Apply may be concurrent; Dispose erases the key and never runs concurrently with them.
// Apply works with the CRT (RFC 8017, Sec. 5.2.1, step 2.b) on a blinded input: m·r^e for a fresh random r, whose inverse unblinds the result, then checks it with RSAVP1. Whether the exponentiations modulo p and q run as a pair (MontgomeryKernelDispatch.CreatePair) depends only on the limb counts of p and q. Nothing that the secrets reach branches on them or indexes by them; only the limb counts of n, p and q set the sizes.
internal sealed class RsaPrivateOperation : IDisposable
{
	private const int ComponentCount = 6;

	private readonly MontgomeryContext _modulus;
	private readonly MontgomeryContext _prime1;
	private readonly MontgomeryContext _prime2;
	private readonly MontgomeryPairContext? _primes;
	private readonly ulong _publicExponent;

	// d, dP, dQ and qInv, with the limbs of n, p, q and p, then the bit lengths of the six components; pinned only so that the GC leaves no copy of them for Dispose to miss.
	private readonly ulong[] _secrets;
	private bool _disposed;

	private RsaPrivateOperation(RsaPublicOperation publicKey, ReadOnlySpan<ulong> modulus, ulong publicExponent, ReadOnlySpan<ulong> d, ReadOnlySpan<ulong> p, ReadOnlySpan<ulong> q, ReadOnlySpan<ulong> dP, ReadOnlySpan<ulong> dQ, ReadOnlySpan<ulong> qInv)
	{
		PublicKey = publicKey;
		_publicExponent = publicExponent;
		_modulus = MontgomeryKernelDispatch.Create(modulus);
		_primes = MontgomeryKernelDispatch.CreatePair(p, q, out _prime1, out _prime2);
		_secrets = GC.AllocateArray<ulong>(d.Length + 2 * p.Length + q.Length + ComponentCount, true);
		d.CopyTo(PrivateExponent);
		dP.CopyTo(Exponent1);
		dQ.CopyTo(Exponent2);
		qInv.CopyTo(Coefficient);

		// The lengths of a generated key are not public until it is exported.
		for (int i = 0; i < ComponentCount; ++i)
		{
			BitLengths[i] = (ulong)Limbs.GetSecretBitLength(GetValue((RsaPrivateComponent)i));
		}
	}

	internal RsaPublicOperation PublicKey { get; }

	private Span<ulong> PrivateExponent => _secrets.AsSpan(0, _modulus.LimbCount);

	private Span<ulong> Exponent1 => _secrets.AsSpan(_modulus.LimbCount, _prime1.LimbCount);

	private Span<ulong> Exponent2 => _secrets.AsSpan(_modulus.LimbCount + _prime1.LimbCount, _prime2.LimbCount);

	private Span<ulong> Coefficient => _secrets.AsSpan(_modulus.LimbCount + _prime1.LimbCount + _prime2.LimbCount, _prime1.LimbCount);

	private Span<ulong> BitLengths => _secrets.AsSpan(_secrets.Length - ComponentCount);

	// Components are unsigned big-endian and may have leading zero bytes; the instance keeps its own copies and does not change the caller's buffers.
	// ArgumentException if the key is invalid; copies owned by the implementation are erased before it throws.
	internal static RsaPrivateOperation Create(RsaPublicOperation publicKey, ReadOnlySpan<byte> privateExponent, ReadOnlySpan<byte> prime1, ReadOnlySpan<byte> prime2, ReadOnlySpan<byte> exponent1, ReadOnlySpan<byte> exponent2, ReadOnlySpan<byte> coefficient)
	{
		ArgumentNullException.ThrowIfNull(publicKey);

		int length = publicKey.ModulusLength;
		Span<byte> exponentBytes = stackalloc byte[publicKey.ExponentLength];
		publicKey.WriteExponent(exponentBytes);
		ulong e = 0;

		foreach (byte b in exponentBytes)
		{
			e = e << 8 | b;
		}

		// The lengths of the components are public, as their encodings show them; only their values are secret. p·q has p.Length + q.Length bytes or one fewer, and the others are below n, p, q and p.
		ReadOnlySpan<byte> p = TrimLeadingZeros(prime1);
		ReadOnlySpan<byte> q = TrimLeadingZeros(prime2);
		ReadOnlySpan<byte> d = TrimLeadingZeros(privateExponent);
		ReadOnlySpan<byte> dP = TrimLeadingZeros(exponent1);
		ReadOnlySpan<byte> dQ = TrimLeadingZeros(exponent2);
		ReadOnlySpan<byte> qInv = TrimLeadingZeros(coefficient);

		if (p.IsEmpty || q.IsEmpty || p.Length + q.Length - 1 > length || p.Length + q.Length < length || d.Length > length || dP.Length > p.Length || dQ.Length > q.Length || qInv.Length > p.Length)
		{
			ThrowInvalidKey();
		}

		int nLimbs = (length + sizeof(ulong) - 1) / sizeof(ulong);
		int pLimbs = (p.Length + sizeof(ulong) - 1) / sizeof(ulong);
		int qLimbs = (q.Length + sizeof(ulong) - 1) / sizeof(ulong);
		int bufferLength = 3 * nLimbs + 3 * pLimbs + 2 * qLimbs;
		using CryptoBuffer<ulong> buffer = CryptoBuffer<ulong>.ShouldUsePool(bufferLength) ? new CryptoBuffer<ulong>(bufferLength) : new CryptoBuffer<ulong>(stackalloc ulong[bufferLength]);
		Span<ulong> rest = buffer.Span;
		Span<ulong> nValue = Take(ref rest, nLimbs);
		Span<ulong> dValue = Take(ref rest, nLimbs);
		Span<ulong> pValue = Take(ref rest, pLimbs);
		Span<ulong> qValue = Take(ref rest, qLimbs);
		Span<ulong> dPValue = Take(ref rest, pLimbs);
		Span<ulong> dQValue = Take(ref rest, qLimbs);
		Span<ulong> qInvValue = Take(ref rest, pLimbs);
		Span<byte> modulusBytes = MemoryMarshal.AsBytes(rest.Slice(0, nLimbs)).Slice(0, length);
		publicKey.WriteModulus(modulusBytes);
		Limbs.FromBigEndian(modulusBytes, nValue);
		Limbs.FromBigEndian(d, dValue);
		Limbs.FromBigEndian(p, pValue);
		Limbs.FromBigEndian(q, qValue);
		Limbs.FromBigEndian(dP, dPValue);
		Limbs.FromBigEndian(dQ, dQValue);
		Limbs.FromBigEndian(qInv, qInvValue);
		rest.Clear();

		if (IsValid(nValue, e, dValue, pValue, qValue, dPValue, dQValue, qInvValue) is 0)
		{
			ThrowInvalidKey();
		}

		return new RsaPrivateOperation(publicKey, nValue, e, dValue, pValue, qValue, dPValue, dQValue, qInvValue);
	}

	// FIPS 186-5, Appendix A.1.3.
	// ArgumentOutOfRangeException: modulusBits is not a multiple of 8 from 2048 to 16384.
	// ArgumentException: publicExponent is even, at most 2^16, or at least 2^33.
	// CryptographicException: four runs of Appendix A.1.3 in a row return FAILURE (see ProbablePrime.Generate).
	internal static RsaPrivateOperation Generate(int modulusBits, ulong publicExponent)
	{
		if (modulusBits is < 2048 or > RsaPublicOperation.MaxModulusBits || modulusBits % 8 is not 0)
		{
			throw new ArgumentOutOfRangeException(nameof(modulusBits), modulusBits, "The modulus must have a multiple of 8 bits from 2048 to 16384.");
		}

		// Appendix A.1.1, criterion 1(b): 2^16 < e < 2^256, odd; RsaPublicOperation takes at most 33 bits.
		if ((publicExponent & 1) is 0 || publicExponent <= 1UL << 16 || publicExponent >= 1UL << RsaPublicOperation.MaxPublicExponentBits)
		{
			throw new ArgumentException("The public exponent must be odd, above 2^16 and below 2^33.", nameof(publicExponent));
		}

		int nLimbs = (modulusBits + 63) / 64;
		int limbs = (modulusBits / 2 + 63) / 64;
		// Pinned, as p stays here while q is searched for.
		using CryptoBuffer<ulong> buffer = new(GC.AllocateUninitializedArray<ulong>(2 * nLimbs + 5 * limbs, true));
		Span<ulong> rest = buffer.Span;
		Span<ulong> n = Take(ref rest, nLimbs);
		Span<ulong> d = Take(ref rest, nLimbs);
		Span<ulong> p = Take(ref rest, limbs);
		Span<ulong> q = Take(ref rest, limbs);
		Span<ulong> dP = Take(ref rest, limbs);
		Span<ulong> dQ = Take(ref rest, limbs);
		Span<ulong> qInv = Take(ref rest, limbs);
		RsaKeyGeneration.Generate(modulusBits, publicExponent, n, p, q, d, dP, dQ, qInv);

		Span<byte> modulusBytes = stackalloc byte[modulusBits / 8];
		Span<byte> exponentBytes = stackalloc byte[sizeof(ulong)];
		Limbs.ToBigEndian(n, modulusBytes);
		BinaryPrimitives.WriteUInt64BigEndian(exponentBytes, publicExponent);
		RsaPublicOperation publicKey = RsaPublicOperation.Create(modulusBytes, exponentBytes);
		return new RsaPrivateOperation(publicKey, n, publicExponent, d, p, q, dP, dQ, qInv);
	}

	// RSASP1 with CRT and blinding, then checked with RSAVP1: input and output are PublicKey.ModulusLength bytes, big-endian; same span allowed, no partial overlap.
	// ArgumentException if input >= n. CryptographicException if the check fails. On any failure output remains unchanged.
	internal void Apply(ReadOnlySpan<byte> input, Span<byte> output)
	{
		ObjectDisposedException.ThrowIf(_disposed, this);

		int length = PublicKey.ModulusLength;
		ArgumentOutOfRangeException.ThrowIfNotEqual(input.Length, length, nameof(input));
		ArgumentOutOfRangeException.ThrowIfNotEqual(output.Length, length, nameof(output));

		if (input.Overlaps(output, out int offset) && offset is not 0)
		{
			ThrowHelper.ThrowSourceDestinationOverlap(nameof(output));
		}

		MontgomeryContext n = _modulus;
		MontgomeryContext p = _prime1;
		MontgomeryContext q = _prime2;
		int nLimbs = n.LimbCount;
		int nDigits = n.DigitCount;
		int pLimbs = p.LimbCount;
		int qLimbs = q.LimbCount;
		int pDigits = p.DigitCount;
		int qDigits = q.DigitCount;
		int bufferLength = 6 * nLimbs + 3 * nDigits + 6 * pLimbs + 5 * qLimbs + 3 * pDigits + qDigits;
		using CryptoBuffer<ulong> buffer = CryptoBuffer<ulong>.ShouldUsePool(bufferLength) ? new CryptoBuffer<ulong>(bufferLength) : new CryptoBuffer<ulong>(stackalloc ulong[bufferLength]);
		Span<ulong> rest = buffer.Span;
		Span<ulong> message = Take(ref rest, nLimbs);
		Span<ulong> random = Take(ref rest, nLimbs);
		Span<ulong> value = Take(ref rest, nLimbs);
		Span<ulong> inverse = Take(ref rest, nLimbs);
		Span<ulong> product = Take(ref rest, pLimbs + qLimbs);
		Span<ulong> blinding = Take(ref rest, nDigits);
		Span<ulong> element = Take(ref rest, nDigits);
		Span<ulong> unblinding = Take(ref rest, nDigits);
		Span<ulong> h = Take(ref rest, pLimbs);
		Span<ulong> sq = Take(ref rest, qLimbs);
		Span<ulong> sp = Take(ref rest, pDigits);
		Span<ulong> term = Take(ref rest, pDigits);
		Span<ulong> coefficient = Take(ref rest, pDigits);
		Span<ulong> modQ = Take(ref rest, qDigits);
		Span<ulong> unblindingP = Take(ref rest, pLimbs);
		Span<ulong> unblindingQ = Take(ref rest, qLimbs);
		Span<ulong> divisorP = Take(ref rest, pLimbs);
		Span<ulong> divisorQ = Take(ref rest, qLimbs);
		Span<ulong> dividendP = Take(ref rest, pLimbs);
		Span<ulong> dividendQ = Take(ref rest, qLimbs);
		Span<byte> signature = MemoryMarshal.AsBytes(Take(ref rest, nLimbs)).Slice(0, length);
		Span<byte> check = MemoryMarshal.AsBytes(Take(ref rest, nLimbs)).Slice(0, length);

		Limbs.FromBigEndian(input, message);

		if (Limbs.LessThan(message, n.Modulus) is 0)
		{
			throw new ArgumentException("The input is not below the modulus.", nameof(input));
		}

		// Blinding: a uniform random r in [1, n), taken as an element, stands for r·R⁻¹; its e-th power and its inverse in the same form unblind each other, whatever r is in plain form.
		DrawBlinding(random, divisorP, divisorQ, sp, modQ);
		n.ToDigits(random, unblinding);
		n.ExponentiateVariableTime(unblinding, _publicExponent, blinding);
		n.ToDigits(message, element);
		// message·(r^e in Montgomery form)·R⁻¹ is the blinded message in plain form.
		n.Multiply(element, element, blinding);
		n.FromDigits(element, value);

		// RFC 8017, Sec. 5.2.1, step 2.b: s1 = c^dP mod p and s2 = c^dQ mod q, h = (s1 − s2)·qInv mod p, s = s2 + q·h.
		q.ToMontgomery(value, modQ);
		p.ToMontgomery(value, sp);

		if (_primes is { } primes)
		{
			primes.Exponentiate(sp, Exponent1, modQ, Exponent2, sp, modQ);
		}
		else
		{
			q.Exponentiate(modQ, Exponent2, modQ);
			p.Exponentiate(sp, Exponent1, sp);
		}

		q.FromMontgomery(modQ, sq);
		Recombine(sp, sq, value, term, coefficient, h, product);

		// Unblinding: R²/(r·R⁻¹) = r⁻¹·R is r⁻¹ in Montgomery form, and multiplying by it leaves plain form. R²/r comes from its residues modulo p and q, recombined as the signature is, as inversions of half the length take less than one of the whole.
		n.WriteRSquared(inverse);
		Divide(p, inverse, divisorP, unblindingP, term, dividendP);
		Divide(q, inverse, divisorQ, unblindingQ, modQ, dividendQ);
		p.ToMontgomery(unblindingP, sp);
		Recombine(sp, unblindingQ, inverse, term, coefficient, h, product);
		n.ToDigits(inverse, unblinding);
		n.ToDigits(value, element);
		n.Multiply(element, element, unblinding);
		n.FromDigits(element, value);
		Limbs.ToBigEndian(value, signature);

		// RSAVP1 on the signature, against the input.
		if (!PublicKey.TryApply(signature, check) || !FixedTime.Equals(check, input))
		{
			throw new CryptographicException("The RSA private key produced a signature that does not verify.");
		}

		signature.CopyTo(output);
	}

	// result = the value modulo n whose residues are element/R mod p, for an element of the context of p, and modQ mod q, by Garner's formula of RFC 8017, Sec. 5.2.1, step 2.b: h = (s1 − s2)·qInv mod p, s = s2 + q·h. element and the rest are scratch.
	private void Recombine(Span<ulong> element, ReadOnlySpan<ulong> modQ, Span<ulong> result, Span<ulong> term, Span<ulong> coefficient, Span<ulong> h, Span<ulong> product)
	{
		MontgomeryContext p = _prime1;
		p.ToMontgomery(modQ, term);
		p.Subtract(element, element, term);
		p.ToDigits(Coefficient, coefficient);
		// (s1 − s2)·R times qInv, times R⁻¹, leaves Montgomery form.
		p.Multiply(element, element, coefficient);
		p.FromDigits(element, h);
		Limbs.Multiply(_prime2.Modulus, h, product);
		result.Clear();
		product.Slice(0, Math.Min(product.Length, result.Length)).CopyTo(result);
		_ = Limbs.AddInPlace(result, modQ);
	}

	// A uniform random r in [1, n) with its residues r·R mod p and mod q, which the unblinding divides by: an r that happens to be a multiple of p or of q has no inverse and is drawn again, which a key of two large primes makes negligibly likely. The residues are checked for zero with masks; elementP and elementQ are scratch.
	// A method of its own, as a loop in Apply would have the JIT optimize Apply in full at once, without the tiers and their profile.
	private void DrawBlinding(Span<ulong> random, Span<ulong> residueP, Span<ulong> residueQ, Span<ulong> elementP, Span<ulong> elementQ)
	{
		do
		{
			DrawBelow(random, _modulus.Modulus);
			ToResidue(_prime1, random, residueP, elementP);
			ToResidue(_prime2, random, residueQ, elementQ);
		}
		while ((Limbs.IsZero(residueP) | Limbs.IsZero(residueQ)) is not 0);
	}

	// result = value·R modulo the modulus of context, below it, for a value of any length below 2^(64·n.LimbCount): the value taken into Montgomery form, then reduced. element is scratch.
	private static void ToResidue(MontgomeryContext context, ReadOnlySpan<ulong> value, Span<ulong> result, Span<ulong> element)
	{
		context.ToMontgomery(value, element);
		context.FromDigits(element, result);
	}

	// result = dividend/divisor modulo the modulus of context, for a dividend below 2^(64·n.LimbCount) and the residue of the divisor that ToResidue gives, which must not be zero: the factors R of the two residues cancel. A modulus that is not prime may still leave the divisor without an inverse, which gives a wrong result that the check after signing rejects. element and dividendResidue are scratch.
	private static void Divide(MontgomeryContext context, ReadOnlySpan<ulong> dividend, ReadOnlySpan<ulong> divisorResidue, Span<ulong> result, Span<ulong> element, Span<ulong> dividendResidue)
	{
		ToResidue(context, dividend, dividendResidue, element);
		ModularInverse.Invert(divisorResidue, dividendResidue, context.Modulus, result);
	}

	// For RSAPrivateKey (RFC 8017, Appendix A.1.2): length without leading zeros, whether its top bit is set, which an INTEGER pads with a zero byte, and the value written into exactly that many bytes.
	internal int GetLength(RsaPrivateComponent component)
	{
		return (GetBitLength(component) + 7) / 8;
	}

	internal bool IsTopBitSet(RsaPrivateComponent component)
	{
		return GetBitLength(component) % 8 is 0;
	}

	internal void Write(RsaPrivateComponent component, Span<byte> destination)
	{
		ArgumentOutOfRangeException.ThrowIfNotEqual(destination.Length, GetLength(component), nameof(destination));

		Limbs.ToBigEndian(GetValue(component), destination);
	}

	public void Dispose()
	{
		if (_disposed)
		{
			return;
		}

		_disposed = true;
		CryptographicOperations.ZeroMemory(MemoryMarshal.AsBytes(_secrets.AsSpan()));
		_primes?.Dispose();
		_prime1.Dispose();
		_prime2.Dispose();
		_modulus.Dispose();
	}

	private int GetBitLength(RsaPrivateComponent component)
	{
		ObjectDisposedException.ThrowIf(_disposed, this);
		ArgumentOutOfRangeException.ThrowIfGreaterThan((uint)component, (uint)RsaPrivateComponent.Coefficient, nameof(component));

		return (int)BitLengths[(int)component];
	}

	private ReadOnlySpan<ulong> GetValue(RsaPrivateComponent component)
	{
		return component switch
		{
			RsaPrivateComponent.PrivateExponent => PrivateExponent,
			RsaPrivateComponent.Prime1 => _prime1.Modulus,
			RsaPrivateComponent.Prime2 => _prime2.Modulus,
			RsaPrivateComponent.Exponent1 => Exponent1,
			RsaPrivateComponent.Exponent2 => Exponent2,
			_ => Coefficient
		};
	}

	// All ones if the key holds: p and q odd, above 1, with p·q = n; 0 < dP < p − 1 with e·dP ≡ 1 (mod p − 1), and likewise dQ; 0 < qInv < p with q·qInv ≡ 1 (mod p); and 0 < d < n with e·d ≡ 1 modulo p − 1 and q − 1. Every check runs, whatever the others give, and none branches on a value.
	private static ulong IsValid(ReadOnlySpan<ulong> n, ulong e, ReadOnlySpan<ulong> d, ReadOnlySpan<ulong> p, ReadOnlySpan<ulong> q, ReadOnlySpan<ulong> dP, ReadOnlySpan<ulong> dQ, ReadOnlySpan<ulong> qInv)
	{
		int nLimbs = n.Length;
		int pLimbs = p.Length;
		int qLimbs = q.Length;
		int bufferLength = 3 * (nLimbs + 1) + 2 * (pLimbs + qLimbs) + pLimbs + qLimbs;
		using CryptoBuffer<ulong> buffer = CryptoBuffer<ulong>.ShouldUsePool(bufferLength) ? new CryptoBuffer<ulong>(bufferLength) : new CryptoBuffer<ulong>(stackalloc ulong[bufferLength]);
		Span<ulong> rest = buffer.Span;
		Span<ulong> product = Take(ref rest, pLimbs + qLimbs);
		Span<ulong> pMinusOne = Take(ref rest, pLimbs);
		Span<ulong> qMinusOne = Take(ref rest, qLimbs);
		Span<ulong> scratch = rest;

		ulong valid = 0 - (p[0] & q[0] & 1);
		valid &= ~Limbs.EqualSmall(p, 1) & ~Limbs.EqualSmall(q, 1);
		Limbs.Multiply(p, q, product);
		valid &= Limbs.Equal(product, n);

		p.CopyTo(pMinusOne);
		q.CopyTo(qMinusOne);
		_ = Limbs.SubtractSmall(pMinusOne, 1);
		_ = Limbs.SubtractSmall(qMinusOne, 1);
		valid &= ~Limbs.IsZero(dP) & Limbs.LessThan(dP, pMinusOne) & IsInverseOfE(e, dP, pMinusOne, scratch);
		valid &= ~Limbs.IsZero(dQ) & Limbs.LessThan(dQ, qMinusOne) & IsInverseOfE(e, dQ, qMinusOne, scratch);

		Limbs.Multiply(q, qInv, product.Slice(0, qLimbs + pLimbs));
		Span<ulong> remainder = scratch.Slice(0, pLimbs);
		Limbs.Remainder(product.Slice(0, qLimbs + pLimbs), p, remainder, scratch.Slice(pLimbs));
		valid &= ~Limbs.IsZero(qInv) & Limbs.LessThan(qInv, p) & Limbs.EqualSmall(remainder, 1);

		valid &= ~Limbs.IsZero(d) & Limbs.LessThan(d, n) & IsInverseOfE(e, d, pMinusOne, scratch) & IsInverseOfE(e, d, qMinusOne, scratch);
		return valid;
	}

	// All ones if e·value ≡ 1 (mod modulus), for a modulus whose top limb is not zero.
	private static ulong IsInverseOfE(ulong e, ReadOnlySpan<ulong> value, ReadOnlySpan<ulong> modulus, Span<ulong> scratch)
	{
		int length = value.Length + 1;
		Span<ulong> t = scratch.Slice(0, length);
		Span<ulong> remainder = scratch.Slice(length, modulus.Length);
		value.CopyTo(t);
		t[^1] = Limbs.MultiplySmall(t.Slice(0, value.Length), e, 0);
		_ = Limbs.SubtractSmall(t, 1);
		Limbs.Remainder(t, modulus, remainder, scratch.Slice(length + modulus.Length));
		ulong result = Limbs.IsZero(remainder);
		scratch.Slice(0, length + modulus.Length).Clear();
		return result;
	}

	// A uniform value in [1, modulus): draws of the bit length of the modulus until one falls in range, which none of the rest of the computation depends on.
	private static void DrawBelow(Span<ulong> value, ReadOnlySpan<ulong> modulus)
	{
		int bits = Limbs.GetBitLength(modulus);
		Span<byte> bytes = MemoryMarshal.AsBytes(value);

		do
		{
			value.Clear();
			SystemRandom.Fill(bytes.Slice(0, (bits + 7) / 8));

			if (!BitConverter.IsLittleEndian)
			{
				for (int i = 0; i < value.Length; ++i)
				{
					value[i] = BinaryPrimitives.ReverseEndianness(value[i]);
				}
			}

			if (bits % 64 is not 0)
			{
				value[bits / 64] &= (1UL << bits % 64) - 1;
			}
		}
		while ((Limbs.LessThan(value, modulus) & ~Limbs.IsZero(value)) is 0);
	}

	private static Span<ulong> Take(ref Span<ulong> rest, int length)
	{
		Span<ulong> taken = rest.Slice(0, length);
		rest = rest.Slice(length);
		return taken;
	}

	private static ReadOnlySpan<byte> TrimLeadingZeros(ReadOnlySpan<byte> value)
	{
		int start = value.IndexOfAnyExcept((byte)0);
		return start < 0 ? default : value.Slice(start);
	}

	[System.Diagnostics.CodeAnalysis.DoesNotReturn]
	private static void ThrowInvalidKey()
	{
		throw new ArgumentException("The RSA private key is invalid.");
	}
}
