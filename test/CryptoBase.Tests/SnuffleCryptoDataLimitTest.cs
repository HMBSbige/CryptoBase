using CryptoBase.SymmetricCryptos.StreamCryptos;

namespace CryptoBase.Tests;

public class SnuffleCryptoDataLimitTest
{
	[Test]
	public async Task ChaCha20()
	{
		byte[] key = new byte[32];
		byte[] iv = new byte[12];
		using ChaCha20Crypto crypto = new(key, iv);

		crypto.SetCounter(uint.MaxValue);
		await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() =>
		{
			crypto.Update(new byte[1], new byte[1]);
			return Task.CompletedTask;
		});

		crypto.Reset();
		crypto.Update(new byte[128], new byte[128]);

		crypto.SetCounter(uint.MaxValue - 1);
		await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() =>
		{
			crypto.Update(new byte[65], new byte[65]);
			return Task.CompletedTask;
		});

		crypto.SetCounter(uint.MaxValue - 1);
		crypto.Update(new byte[64], new byte[64]);
		await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() =>
		{
			crypto.Update(new byte[1], new byte[1]);
			return Task.CompletedTask;
		});

		crypto.SetCounter(uint.MaxValue - 1);
		crypto.Update(new byte[64], new byte[64]);
	}

	[Test]
	public async Task Salsa20()
	{
		byte[] key = new byte[32];
		byte[] iv = new byte[8];
		using Salsa20Crypto crypto = new(key, iv);

		crypto.SetCounter(ulong.MaxValue);
		await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() =>
		{
			crypto.Update(new byte[1], new byte[1]);
			return Task.CompletedTask;
		});

		crypto.Reset();
		crypto.Update(new byte[128], new byte[128]);

		crypto.SetCounter(ulong.MaxValue - 1);
		await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() =>
		{
			crypto.Update(new byte[65], new byte[65]);
			return Task.CompletedTask;
		});

		crypto.SetCounter(ulong.MaxValue - 1);
		crypto.Update(new byte[64], new byte[64]);
		await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() =>
		{
			crypto.Update(new byte[1], new byte[1]);
			return Task.CompletedTask;
		});

		crypto.SetCounter(ulong.MaxValue - 1);
		crypto.Update(new byte[64], new byte[64]);
	}

	[Test]
	public async Task ChaCha20Original()
	{
		byte[] key = new byte[32];
		byte[] iv = new byte[8];
		using ChaCha20OriginalCrypto crypto = new(key, iv);

		crypto.SetCounter(ulong.MaxValue);
		await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() =>
		{
			crypto.Update(new byte[1], new byte[1]);
			return Task.CompletedTask;
		});

		crypto.Reset();
		crypto.Update(new byte[128], new byte[128]);

		crypto.SetCounter(ulong.MaxValue - 1);
		await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() =>
		{
			crypto.Update(new byte[65], new byte[65]);
			return Task.CompletedTask;
		});

		crypto.SetCounter(ulong.MaxValue - 1);
		crypto.Update(new byte[64], new byte[64]);
		await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() =>
		{
			crypto.Update(new byte[1], new byte[1]);
			return Task.CompletedTask;
		});

		crypto.SetCounter(ulong.MaxValue - 1);
		crypto.Update(new byte[64], new byte[64]);
	}

	[Test]
	public async Task XChaCha20()
	{
		byte[] key = new byte[32];
		byte[] iv = new byte[24];
		using XChaCha20Crypto crypto = new(key, iv);

		crypto.SetCounter(ulong.MaxValue);
		await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() =>
		{
			crypto.Update(new byte[1], new byte[1]);
			return Task.CompletedTask;
		});

		crypto.Reset();
		crypto.Update(new byte[128], new byte[128]);

		crypto.SetCounter(ulong.MaxValue - 1);
		await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() =>
		{
			crypto.Update(new byte[65], new byte[65]);
			return Task.CompletedTask;
		});

		crypto.SetCounter(ulong.MaxValue - 1);
		crypto.Update(new byte[64], new byte[64]);
		await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() =>
		{
			crypto.Update(new byte[1], new byte[1]);
			return Task.CompletedTask;
		});

		crypto.SetCounter(ulong.MaxValue - 1);
		crypto.Update(new byte[64], new byte[64]);
	}

	[Test]
	public async Task XSalsa20()
	{
		byte[] key = new byte[32];
		byte[] iv = new byte[24];
		using XSalsa20Crypto crypto = new(key, iv);

		crypto.SetCounter(ulong.MaxValue);
		await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() =>
		{
			crypto.Update(new byte[1], new byte[1]);
			return Task.CompletedTask;
		});

		crypto.Reset();
		crypto.Update(new byte[128], new byte[128]);

		crypto.SetCounter(ulong.MaxValue - 1);
		await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() =>
		{
			crypto.Update(new byte[65], new byte[65]);
			return Task.CompletedTask;
		});

		crypto.SetCounter(ulong.MaxValue - 1);
		crypto.Update(new byte[64], new byte[64]);
		await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() =>
		{
			crypto.Update(new byte[1], new byte[1]);
			return Task.CompletedTask;
		});

		crypto.SetCounter(ulong.MaxValue - 1);
		crypto.Update(new byte[64], new byte[64]);
	}
}
