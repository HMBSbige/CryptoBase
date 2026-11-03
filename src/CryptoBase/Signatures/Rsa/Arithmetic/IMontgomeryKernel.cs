namespace CryptoBase.Signatures.Rsa.Arithmetic;

// Montgomery arithmetic modulo an odd n, on elements of digitCount digits of DigitBits bits each, one digit per ulong, least significant first. An element x stands for x·R⁻¹ mod n, with R = 2^(DigitBits·digitCount) ≥ 4n.
// Elements need not be reduced: Multiply and Square take values below 2n and give values below 2n, so that a chain of them needs no subtraction of n until the end. Every digit of an input must be below 2^DigitBits, and so is every digit of an output.
// The methods that run for every operation are optimized from their first call, since few processes reach the call counts that tier them up before most of their operations have run.
// The modulus comes as Prepare writes it, with negativeInverse = −n⁻¹ mod 2^DigitBits. Neither the time nor the addresses may depend on the elements or on the modulus, only on digitCount, which must not exceed MaxDigitCount, and on where the spans lie. result may be the same span as an input but must not overlap one otherwise; scratch, of GetScratchLength(digitCount) words, overlaps none of them. A kernel erases nothing; the caller erases scratch.
internal interface IMontgomeryKernel
{
	static abstract bool IsSupported { get; }

	static abstract int DigitBits { get; }

	// The most digits for which the sums of a column cannot overflow a word.
	static abstract int MaxDigitCount { get; }

	static abstract int GetScratchLength(int digitCount);

	// prepared has digitCount words, as many as the digits of the modulus.
	static abstract void Prepare(ReadOnlySpan<ulong> modulus, Span<ulong> prepared);

	// result = left·right·R⁻¹ mod n. In: left and right below 2n; or left any value of digitCount digits and right below n. Out: below 2n.
	static abstract void Multiply(Span<ulong> result, ReadOnlySpan<ulong> left, ReadOnlySpan<ulong> right, ReadOnlySpan<ulong> modulus, ulong negativeInverse, Span<ulong> scratch);

	// result = value²·R⁻¹ mod n. In: below 2n. Out: below 2n.
	static abstract void Square(Span<ulong> result, ReadOnlySpan<ulong> value, ReadOnlySpan<ulong> modulus, ulong negativeInverse, Span<ulong> scratch);
}
