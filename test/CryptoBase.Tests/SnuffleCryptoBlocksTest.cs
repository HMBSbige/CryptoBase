using CryptoBase.Abstractions.SymmetricCryptos;
using CryptoBase.SymmetricCryptos.StreamCryptos;
using System.Security.Cryptography;

namespace CryptoBase.Tests;

public class SnuffleCryptoBlocksTest
{
	public static TheoryData<int> LengthData =>
	[
		2 * 64 - 1,
		4 * 64 - 1,
		8 * 64 - 1,
		16 * 64 - 1,
		32 * 64 - 1,
		64 * 64 - 1,
		128 * 64 - 1
	];

	[Theory]
	[MemberData(nameof(LengthData))]
	public void ChaCha20(int length)
	{
		using IStreamCrypto crypto = new ChaCha20Crypto(RandomNumberGenerator.GetBytes(32), RandomNumberGenerator.GetBytes(12));
		TestUtils.TestBlocks(crypto, length);
	}

	[Theory]
	[MemberData(nameof(LengthData))]
	public void ChaCha20Original(int length)
	{
		using IStreamCrypto crypto = new ChaCha20OriginalCrypto(RandomNumberGenerator.GetBytes(32), RandomNumberGenerator.GetBytes(8));
		TestUtils.TestBlocks(crypto, length);
	}

	[Theory]
	[MemberData(nameof(LengthData))]
	public void XChaCha20(int length)
	{
		using IStreamCrypto crypto = new XChaCha20Crypto(RandomNumberGenerator.GetBytes(32), RandomNumberGenerator.GetBytes(24));
		TestUtils.TestBlocks(crypto, length);
	}

	[Theory]
	[MemberData(nameof(LengthData))]
	public void Salsa20(int length)
	{
		using IStreamCrypto crypto = new Salsa20Crypto(RandomNumberGenerator.GetBytes(32), RandomNumberGenerator.GetBytes(8));
		TestUtils.TestBlocks(crypto, length);
	}

	[Theory]
	[MemberData(nameof(LengthData))]
	public void XSalsa20(int length)
	{
		using IStreamCrypto crypto = new XSalsa20Crypto(RandomNumberGenerator.GetBytes(32), RandomNumberGenerator.GetBytes(24));
		TestUtils.TestBlocks(crypto, length);
	}
}
