namespace CryptoBase.Signatures.Rsa.Arithmetic;

// Montgomery arithmetic modulo two odd moduli of one digit count at once, in the digits of a single kernel: a pair interleaves an element of each, word 2j holding digit j of the first and word 2j + 1 digit j of the second, and each half is an element of its modulus with the bounds of IMontgomeryKernel. Neither the time nor the addresses may depend on the elements or on the moduli, only on digitCount, from MinDigitCount to MaxDigitCount, and on where the spans lie.
// result may be the same span as an input but must not overlap one otherwise; scratch, of GetScratchLength(digitCount) words, overlaps none of them. A kernel erases nothing; the caller erases scratch.
internal interface IMontgomeryPairKernel
{
	static abstract bool IsSupported { get; }

	static abstract int DigitBits { get; }

	static abstract int MinDigitCount { get; }

	static abstract int MaxDigitCount { get; }

	static abstract int GetScratchLength(int digitCount);

	// moduli interleaves the digits of the two moduli, as the kernel takes them.
	static abstract void Prepare(ReadOnlySpan<ulong> first, ReadOnlySpan<ulong> second, Span<ulong> moduli);

	// result = left·right·R⁻¹ modulo each modulus, whose −n⁻¹ mod 2^DigitBits are firstInverse and secondInverse. In and out as IMontgomeryKernel.Multiply.
	static abstract void Multiply(Span<ulong> result, ReadOnlySpan<ulong> left, ReadOnlySpan<ulong> right, ReadOnlySpan<ulong> moduli, ulong firstInverse, ulong secondInverse, Span<ulong> scratch);

	static abstract void Square(Span<ulong> result, ReadOnlySpan<ulong> value, ReadOnlySpan<ulong> moduli, ulong firstInverse, ulong secondInverse, Span<ulong> scratch);
}
