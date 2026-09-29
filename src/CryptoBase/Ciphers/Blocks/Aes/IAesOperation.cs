namespace CryptoBase.Ciphers.Blocks.Aes;

internal interface IAesOperation
{
	static abstract Vector128<byte> Apply1<TCore>(ref TCore core, Vector128<byte> value) where TCore : struct, IAesVectorCore;
	static abstract void Apply2<TCore>(ref TCore core, ref Vector128<byte> v0, ref Vector128<byte> v1) where TCore : struct, IAesVectorCore;
	static abstract void Apply4<TCore>(ref TCore core, ref Vector128<byte> v0, ref Vector128<byte> v1, ref Vector128<byte> v2, ref Vector128<byte> v3) where TCore : struct, IAesVectorCore;
	static abstract void Apply8<TCore>(ref TCore core, ref Vector128<byte> v0, ref Vector128<byte> v1, ref Vector128<byte> v2, ref Vector128<byte> v3, ref Vector128<byte> v4, ref Vector128<byte> v5, ref Vector128<byte> v6, ref Vector128<byte> v7) where TCore : struct, IAesVectorCore;

	static abstract Vector128<byte> Apply1(in AesCipherVpaes core, Vector128<byte> value);
	static abstract void Apply2(in AesCipherVpaes core, ref Vector128<byte> v0, ref Vector128<byte> v1);
	static abstract void Apply3(in AesCipherVpaes core, ref Vector128<byte> v0, ref Vector128<byte> v1, ref Vector128<byte> v2);
	static abstract void Apply4(in AesCipherVpaes core, ref Vector128<byte> v0, ref Vector128<byte> v1, ref Vector128<byte> v2, ref Vector128<byte> v3);
	static abstract void ApplyBatch<TPolicy>(in AesCipherBitslice core, ref TPolicy policy, ref byte input, ref byte output, nuint offset, int length, int rounds) where TPolicy : struct, IAesModePolicy, allows ref struct;
	static abstract void ApplyBlocks(in AesCipherSoftware core, ReadOnlySpan<byte> source, Span<byte> destination);
}
