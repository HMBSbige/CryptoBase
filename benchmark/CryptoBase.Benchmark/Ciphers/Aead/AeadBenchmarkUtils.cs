using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;

namespace CryptoBase.Benchmark.Ciphers.Aead;

internal static class AeadBenchmarkUtils
{
	// Encrypts with a 128-bit tag, which BouncyCastle appends to the ciphertext in destination.
	public static void BouncyCastleEncrypt(IAeadCipher engine, KeyParameter key, byte[] nonce, ReadOnlySpan<byte> source, Span<byte> destination, ReadOnlySpan<byte> associatedData)
	{
		engine.Init(true, new AeadParameters(key, 128, nonce));
		engine.ProcessAadBytes(associatedData);
		int written = engine.ProcessBytes(source, destination);
		engine.DoFinal(destination.Slice(written));
	}
}
