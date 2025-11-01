using CryptoBase.SymmetricCryptos.StreamCryptos;

namespace CryptoBase.Tests;

public class SnuffleCryptoDataLimitTest
{
	[Fact]
	public void ChaCha20()
	{
		byte[] key = new byte[32];
		byte[] iv = new byte[12];
		using ChaCha20Crypto crypto = new(key, iv);

		crypto.SetCounter(uint.MaxValue);
		Assert.Throws<ArgumentOutOfRangeException>(() => crypto.Update(new byte[1], new byte[1]));

		crypto.Reset();
		crypto.Update(new byte[128], new byte[128]);

		crypto.SetCounter(uint.MaxValue - 1);
		Assert.Throws<ArgumentOutOfRangeException>(() => crypto.Update(new byte[65], new byte[65]));

		crypto.SetCounter(uint.MaxValue - 1);
		crypto.Update(new byte[64], new byte[64]);
		Assert.Throws<ArgumentOutOfRangeException>(() => crypto.Update(new byte[1], new byte[1]));

		crypto.SetCounter(uint.MaxValue - 1);
		crypto.Update(new byte[64], new byte[64]);
	}

	[Fact]
	public void Salsa20()
	{
		byte[] key = new byte[32];
		byte[] iv = new byte[8];
		using Salsa20Crypto crypto = new(key, iv);

		crypto.SetCounter(ulong.MaxValue);
		Assert.Throws<ArgumentOutOfRangeException>(() => crypto.Update(new byte[1], new byte[1]));

		crypto.Reset();
		crypto.Update(new byte[128], new byte[128]);

		crypto.SetCounter(ulong.MaxValue - 1);
		Assert.Throws<ArgumentOutOfRangeException>(() => crypto.Update(new byte[65], new byte[65]));

		crypto.SetCounter(ulong.MaxValue - 1);
		crypto.Update(new byte[64], new byte[64]);
		Assert.Throws<ArgumentOutOfRangeException>(() => crypto.Update(new byte[1], new byte[1]));

		crypto.SetCounter(ulong.MaxValue - 1);
		crypto.Update(new byte[64], new byte[64]);
	}

	[Fact]
	public void ChaCha20Original()
	{
		byte[] key = new byte[32];
		byte[] iv = new byte[8];
		using ChaCha20OriginalCrypto crypto = new(key, iv);

		crypto.SetCounter(ulong.MaxValue);
		Assert.Throws<ArgumentOutOfRangeException>(() => crypto.Update(new byte[1], new byte[1]));

		crypto.Reset();
		crypto.Update(new byte[128], new byte[128]);

		crypto.SetCounter(ulong.MaxValue - 1);
		Assert.Throws<ArgumentOutOfRangeException>(() => crypto.Update(new byte[65], new byte[65]));

		crypto.SetCounter(ulong.MaxValue - 1);
		crypto.Update(new byte[64], new byte[64]);
		Assert.Throws<ArgumentOutOfRangeException>(() => crypto.Update(new byte[1], new byte[1]));

		crypto.SetCounter(ulong.MaxValue - 1);
		crypto.Update(new byte[64], new byte[64]);
	}

	[Fact]
	public void XChaCha20()
	{
		byte[] key = new byte[32];
		byte[] iv = new byte[24];
		using XChaCha20Crypto crypto = new(key, iv);

		crypto.SetCounter(ulong.MaxValue);
		Assert.Throws<ArgumentOutOfRangeException>(() => crypto.Update(new byte[1], new byte[1]));

		crypto.Reset();
		crypto.Update(new byte[128], new byte[128]);

		crypto.SetCounter(ulong.MaxValue - 1);
		Assert.Throws<ArgumentOutOfRangeException>(() => crypto.Update(new byte[65], new byte[65]));

		crypto.SetCounter(ulong.MaxValue - 1);
		crypto.Update(new byte[64], new byte[64]);
		Assert.Throws<ArgumentOutOfRangeException>(() => crypto.Update(new byte[1], new byte[1]));

		crypto.SetCounter(ulong.MaxValue - 1);
		crypto.Update(new byte[64], new byte[64]);
	}

	[Fact]
	public void XSalsa20()
	{
		byte[] key = new byte[32];
		byte[] iv = new byte[24];
		using XSalsa20Crypto crypto = new(key, iv);

		crypto.SetCounter(ulong.MaxValue);
		Assert.Throws<ArgumentOutOfRangeException>(() => crypto.Update(new byte[1], new byte[1]));

		crypto.Reset();
		crypto.Update(new byte[128], new byte[128]);

		crypto.SetCounter(ulong.MaxValue - 1);
		Assert.Throws<ArgumentOutOfRangeException>(() => crypto.Update(new byte[65], new byte[65]));

		crypto.SetCounter(ulong.MaxValue - 1);
		crypto.Update(new byte[64], new byte[64]);
		Assert.Throws<ArgumentOutOfRangeException>(() => crypto.Update(new byte[1], new byte[1]));

		crypto.SetCounter(ulong.MaxValue - 1);
		crypto.Update(new byte[64], new byte[64]);
	}
}
