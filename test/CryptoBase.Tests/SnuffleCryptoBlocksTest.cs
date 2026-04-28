using CryptoBase.Abstractions.SymmetricCryptos;
using CryptoBase.SymmetricCryptos.StreamCryptos;
using System.Security.Cryptography;

namespace CryptoBase.Tests;

public class SnuffleCryptoBlocksTest
{
	public static IEnumerable<int> LengthData =>
	[
		2 * 64 - 1,
		4 * 64 - 1,
		8 * 64 - 1,
		16 * 64 - 1,
		32 * 64 - 1,
		64 * 64 - 1,
		128 * 64 - 1
	];

	[Test]
	[MethodDataSource(nameof(LengthData))]
	public async Task ChaCha20(int length)
	{
		using IStreamCrypto crypto = new ChaCha20Crypto(RandomNumberGenerator.GetBytes(32), RandomNumberGenerator.GetBytes(12));
		await TestUtils.TestBlocks(crypto, length);
	}

	[Test]
	[MethodDataSource(nameof(LengthData))]
	public async Task ChaCha20Original(int length)
	{
		using IStreamCrypto crypto = new ChaCha20OriginalCrypto(RandomNumberGenerator.GetBytes(32), RandomNumberGenerator.GetBytes(8));
		await TestUtils.TestBlocks(crypto, length);
	}

	[Test]
	[MethodDataSource(nameof(LengthData))]
	public async Task XChaCha20(int length)
	{
		using IStreamCrypto crypto = new XChaCha20Crypto(RandomNumberGenerator.GetBytes(32), RandomNumberGenerator.GetBytes(24));
		await TestUtils.TestBlocks(crypto, length);
	}

	[Test]
	[MethodDataSource(nameof(LengthData))]
	public async Task Salsa20(int length)
	{
		using IStreamCrypto crypto = new Salsa20Crypto(RandomNumberGenerator.GetBytes(32), RandomNumberGenerator.GetBytes(8));
		await TestUtils.TestBlocks(crypto, length);
	}

	[Test]
	[MethodDataSource(nameof(LengthData))]
	public async Task XSalsa20(int length)
	{
		using IStreamCrypto crypto = new XSalsa20Crypto(RandomNumberGenerator.GetBytes(32), RandomNumberGenerator.GetBytes(24));
		await TestUtils.TestBlocks(crypto, length);
	}
}
