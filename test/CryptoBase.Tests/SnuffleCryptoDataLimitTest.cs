using CryptoBase.SymmetricCryptos.StreamCryptos;

namespace CryptoBase.Tests;

public class SnuffleCryptoDataLimitTest
{
	[Fact]
	public void ChaCha20_ThrowsWhenDataLimitExceeded()
	{
		// ChaCha20 has a 32-bit counter, max = 2^32 * 64 bytes = 274,877,906,944 bytes
		byte[] key = new byte[32];
		byte[] iv = new byte[12];
		using var crypto = new ChaCha20Crypto(key, iv);

		// Set counter to near the limit
		uint maxCounter = uint.MaxValue;
		crypto.SetCounter(maxCounter);

		// Try to process more than one block, which would cause counter overflow
		byte[] input = new byte[128]; // 2 blocks
		byte[] output = new byte[128];

		Assert.Throws<ArgumentOutOfRangeException>(() => crypto.Update(input, output));
	}

	[Fact]
	public void ChaCha20_WorksWhenNearLimitButNotExceeding()
	{
		// ChaCha20 has a 32-bit counter, max = 2^32 * 64 bytes
		byte[] key = new byte[32];
		byte[] iv = new byte[12];
		using var crypto = new ChaCha20Crypto(key, iv);

		// Set counter to near the limit
		uint maxCounter = uint.MaxValue;
		crypto.SetCounter(maxCounter);

		// Process exactly one block - should work
		byte[] input = new byte[64];
		byte[] output = new byte[64];

		crypto.Update(input, output); // Should not throw
	}

	[Fact]
	public void ChaCha20_ThrowsWhenProcessingExceedsLimit()
	{
		byte[] key = new byte[32];
		byte[] iv = new byte[12];
		using var crypto = new ChaCha20Crypto(key, iv);

		// Set counter near the end
		uint nearMaxCounter = uint.MaxValue - 5;
		crypto.SetCounter(nearMaxCounter);

		// Process 5 blocks successfully
		byte[] input = new byte[64 * 5];
		byte[] output = new byte[64 * 5];
		crypto.Update(input, output); // Should work

		// Process one more block successfully (at counter = uint.MaxValue)
		byte[] input2 = new byte[64];
		byte[] output2 = new byte[64];
		crypto.Update(input2, output2); // Should work - this is the last valid block

		// Try to process one more block - should fail (would need counter = 2^32, which overflows)
		byte[] input3 = new byte[64];
		byte[] output3 = new byte[64];
		Assert.Throws<ArgumentOutOfRangeException>(() => crypto.Update(input3, output3));
	}

	[Fact]
	public void ChaCha20_ResetAllowsReprocessing()
	{
		byte[] key = new byte[32];
		byte[] iv = new byte[12];
		using var crypto = new ChaCha20Crypto(key, iv);

		// Set counter to the maximum
		crypto.SetCounter(uint.MaxValue);

		// Try to process - should fail
		byte[] input = new byte[128];
		byte[] output = new byte[128];
		Assert.Throws<ArgumentOutOfRangeException>(() => crypto.Update(input, output));

		// Reset and try again - should work
		crypto.Reset();
		crypto.Update(input, output); // Should not throw
	}

	[Fact]
	public void Salsa20_DoesNotThrowForLargeData()
	{
		// Salsa20 has a 64-bit counter, effectively unlimited
		byte[] key = new byte[32];
		byte[] iv = new byte[8];
		using var crypto = new Salsa20Crypto(key, iv);

		// Process multiple blocks without issues
		byte[] input = new byte[64 * 1000];
		byte[] output = new byte[64 * 1000];
		crypto.Update(input, output); // Should not throw
	}

	[Fact]
	public void ChaCha20Original_DoesNotThrowForLargeData()
	{
		// ChaCha20Original has a 64-bit counter, effectively unlimited
		byte[] key = new byte[32];
		byte[] iv = new byte[8];
		using var crypto = new ChaCha20OriginalCrypto(key, iv);

		// Process multiple blocks without issues
		byte[] input = new byte[64 * 1000];
		byte[] output = new byte[64 * 1000];
		crypto.Update(input, output); // Should not throw
	}

	[Fact]
	public void XChaCha20_DoesNotThrowForLargeData()
	{
		// XChaCha20 uses 64-bit counter (inherits from ChaCha20Original)
		byte[] key = new byte[32];
		byte[] iv = new byte[24];
		using var crypto = new XChaCha20Crypto(key, iv);

		// Process multiple blocks without issues
		byte[] input = new byte[64 * 1000];
		byte[] output = new byte[64 * 1000];
		crypto.Update(input, output); // Should not throw
	}

	[Fact]
	public void XSalsa20_DoesNotThrowForLargeData()
	{
		// XSalsa20 uses 64-bit counter (inherits from Salsa20)
		byte[] key = new byte[32];
		byte[] iv = new byte[24];
		using var crypto = new XSalsa20Crypto(key, iv);

		// Process multiple blocks without issues
		byte[] input = new byte[64 * 1000];
		byte[] output = new byte[64 * 1000];
		crypto.Update(input, output); // Should not throw
	}

	[Fact]
	public void ChaCha20_BytesProcessedTrackedCorrectly()
	{
		byte[] key = new byte[32];
		byte[] iv = new byte[12];
		using var crypto = new ChaCha20Crypto(key, iv);

		// Process some data
		byte[] input = new byte[100];
		byte[] output = new byte[100];
		crypto.Update(input, output);

		// Process more data
		byte[] input2 = new byte[200];
		byte[] output2 = new byte[200];
		crypto.Update(input2, output2);

		// Both should succeed - total 300 bytes is well within limit
	}

	[Fact]
	public void ChaCha20_SetCounterUpdatesLimit()
	{
		byte[] key = new byte[32];
		byte[] iv = new byte[12];
		using var crypto = new ChaCha20Crypto(key, iv);

		// Process some blocks
		byte[] input = new byte[64];
		byte[] output = new byte[64];
		crypto.Update(input, output);

		// Set counter to a high value
		crypto.SetCounter(uint.MaxValue - 10);

		// Process 11 blocks - should work (10 blocks to reach MaxValue, plus 1 at MaxValue)
		byte[] input2 = new byte[64 * 11];
		byte[] output2 = new byte[64 * 11];
		crypto.Update(input2, output2);

		// Try one more - should fail
		Assert.Throws<ArgumentOutOfRangeException>(() => crypto.Update(input, output));
	}
}
