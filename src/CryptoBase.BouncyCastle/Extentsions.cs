using Org.BouncyCastle.Crypto.Modes;
using System.Buffers;

namespace CryptoBase.BouncyCastle;

internal static class Extentsions
{
	public static void AeadEncrypt(this IAeadCipher engine, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> source, Span<byte> destination, Span<byte> tag, ReadOnlySpan<byte> associatedData = default)
	{
		engine.ProcessAadBytes(associatedData);

		int o = engine.ProcessBytes(source, destination);

		int restSize = source.Length - o;
		byte[] rest = ArrayPool<byte>.Shared.Rent(restSize + 16);

		try
		{
			engine.DoFinal(rest.AsSpan(0, restSize + 16));
			rest.AsSpan(0, restSize).CopyTo(destination.Slice(o));
			rest.AsSpan(restSize, 16).CopyTo(tag);
		}
		finally
		{
			ArrayPool<byte>.Shared.Return(rest);
		}
	}

	public static void AeadDecrypt(this IAeadCipher engine, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> source, ReadOnlySpan<byte> tag, Span<byte> destination, ReadOnlySpan<byte> associatedData = default)
	{
		engine.ProcessAadBytes(associatedData);

		int o0 = engine.ProcessBytes(source, destination);
		int o1 = engine.ProcessBytes(tag, destination.Slice(o0));
		engine.DoFinal(destination.Slice(o0 + o1));
	}
}
