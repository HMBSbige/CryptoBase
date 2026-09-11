namespace CryptoBase.Macs.Poly1305;

internal interface IPoly1305State<TSelf> where TSelf : unmanaged, IPoly1305State<TSelf>, allows ref struct
{
	static abstract bool IsSupported { get; }

	static abstract void Initialize(ref TSelf state, scoped ReadOnlySpan<byte> key);

	/// <summary>
	/// Processes the supplied data as one complete Poly1305 message.
	/// </summary>
	void AppendMessage(scoped ReadOnlySpan<byte> source);

	/// <summary>
	/// Processes the supplied data as one zero-padded AEAD segment.
	/// </summary>
	void AppendPaddedSegment(scoped ReadOnlySpan<byte> source);

	void WriteMac(scoped Span<byte> destination);
}
