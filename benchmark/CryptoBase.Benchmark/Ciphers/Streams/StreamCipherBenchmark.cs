using BenchmarkDotNet.Attributes;
using CryptoBase.Abstractions.Ciphers;
using CryptoBase.Ciphers.Streams;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;
using System.Security.Cryptography;
using BouncyCastleStreamCipher = Org.BouncyCastle.Crypto.IStreamCipher;

namespace CryptoBase.Benchmark.Ciphers.Streams;

public class ChaCha20Benchmark() : StreamCipherBenchmark<ChaCha20Cipher, ChaCha7539Engine>(12, (key, iv) => new ChaCha20Cipher(key, iv));

public class ChaCha20OriginalBenchmark() : StreamCipherBenchmark<ChaCha20OriginalCipher, ChaChaEngine>(8, (key, iv) => new ChaCha20OriginalCipher(key, iv));

public class Salsa20Benchmark() : StreamCipherBenchmark<Salsa20Cipher, Salsa20Engine>(8, (key, iv) => new Salsa20Cipher(key, iv));

public class XSalsa20Benchmark() : StreamCipherBenchmark<XSalsa20Cipher, XSalsa20Engine>(24, (key, iv) => new XSalsa20Cipher(key, iv));

// A 32-byte key and an IV of ivLength bytes, for CryptoBase and the BouncyCastle engine alike.
[MemoryDiagnoser]
public abstract class StreamCipherBenchmark<TCipher, TEngine>(int ivLength, Func<byte[], byte[], TCipher> create) : StreamCipherBenchmarkBase
	where TCipher : IStreamCipher
	where TEngine : BouncyCastleStreamCipher, new()
{
	private TCipher _crypto = default!;
	private readonly TEngine _bcEngine = new();

	protected override void SetupCryptos()
	{
		byte[] key = RandomNumberGenerator.GetBytes(32);
		byte[] iv = RandomNumberGenerator.GetBytes(ivLength);

		_crypto = Register(create(key, iv));
		_bcEngine.Init(false, new ParametersWithIV(new KeyParameter(key), iv));
	}

	[Benchmark(Baseline = true)]
	public void CryptoBase()
	{
		Run(_crypto);
	}

	[Benchmark]
	public void BouncyCastle()
	{
		_bcEngine.ProcessBytes(Input, Output);
	}
}
