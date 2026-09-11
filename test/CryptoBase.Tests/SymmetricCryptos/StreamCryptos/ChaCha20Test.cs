using CryptoBase.SymmetricCryptos.StreamCryptos;

namespace CryptoBase.Tests.SymmetricCryptos.StreamCryptos;

public class ChaCha20Test
{
	[Test]
	public async Task Rfc8439EncryptionVectorAndReset()
	{
		byte[] key = Convert.FromHexString("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F");
		byte[] nonce = Convert.FromHexString("000000000000004A00000000");
		byte[] plaintext = Convert.FromHexString("4C616469657320616E642047656E746C656D656E206F662074686520636C617373206F66202739393A204966204920636F756C64206F6666657220796F75206F6E6C79206F6E652074697020666F7220746865206675747572652C2073756E73637265656E20776F756C642062652069742E");
		byte[] expected = Convert.FromHexString("6E2E359A2568F98041BA0728DD0D6981E97E7AEC1D4360C20A27AFCCFD9FAE0BF91B65C5524733AB8F593DABCD62B3571639D624E65152AB8F530C359F0861D807CA0DBF500D6A6156A38E088A22B65E52BC514D16CCF806818CE91AB77937365AF90BBF74A35BE6B40B8EEDF2785E42874D");
		byte[] actual = new byte[plaintext.Length];
		using ChaCha20Crypto crypto = new(key, nonce);
		crypto.SetCounter(1);

		crypto.Update(plaintext, actual);

		await Assert.That(crypto.Name).IsEqualTo("ChaCha20");
		await Assert.That(crypto.IVSize).IsEqualTo(12);
		await Assert.That(actual).IsEquivalentTo(expected, CollectionOrdering.Matching);

		crypto.Reset();
		using ChaCha20Crypto oracle = new(key, nonce);
		crypto.Update(plaintext, actual);
		oracle.Update(plaintext, expected);
		await Assert.That(actual).IsEquivalentTo(expected, CollectionOrdering.Matching);
	}
}
