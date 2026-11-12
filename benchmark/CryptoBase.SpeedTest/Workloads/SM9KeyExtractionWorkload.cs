using CryptoBase.SM9;

namespace CryptoBase.SpeedTest.Workloads;

/// <summary>
/// Extracts the private key of an ID from a master key once per iteration, which is the key generation of SM9.
/// </summary>
/// <remarks>
/// Each iteration also exports the key, which costs nothing next to the scalar multiplication that extracts it.
/// </remarks>
internal sealed class SM9KeyExtractionWorkload : Workload
{
	private static readonly byte[] Id = "alice@example.com"u8.ToArray();

	private readonly IDisposable _master;
	private readonly KeyExtractor _extract;
	private readonly byte[] _privateKey;

	private SM9KeyExtractionWorkload(IDisposable master, int privateKeyLength, KeyExtractor extract)
	{
		_master = master;
		_extract = extract;
		_privateKey = new byte[privateKeyLength];
	}

	private delegate void KeyExtractor(ReadOnlySpan<byte> id, Span<byte> privateKey);

	public static SM9KeyExtractionWorkload ForSignature()
	{
		SM9SignatureMasterKey master = SM9SignatureMasterKey.GenerateKey();

		return new SM9KeyExtractionWorkload(master, SM9SignatureKey.PrivateKeyLength, (id, privateKey) =>
		{
			using SM9SignatureKey key = master.ExtractKey(id);
			key.ExportPrivateKey(privateKey);
		});
	}

	public static SM9KeyExtractionWorkload ForEncryption()
	{
		SM9EncryptionMasterKey master = SM9EncryptionMasterKey.GenerateKey();

		return new SM9KeyExtractionWorkload(master, SM9EncryptionKey.PrivateKeyLength, (id, privateKey) =>
		{
			using SM9EncryptionKey key = master.ExtractKey(id);
			key.ExportPrivateKey(privateKey);
		});
	}

	public static SM9KeyExtractionWorkload ForKeyExchange()
	{
		SM9EncryptionMasterKey master = SM9EncryptionMasterKey.GenerateKey();

		return new SM9KeyExtractionWorkload(master, SM9KeyExchangeKey.PrivateKeyLength, (id, privateKey) =>
		{
			using SM9KeyExchangeKey key = master.ExtractKeyExchangeKey(id);
			key.ExportPrivateKey(privateKey);
		});
	}

	public override void Verify()
	{
		byte[] first = new byte[_privateKey.Length];
		byte[] second = new byte[_privateKey.Length];
		byte[] other = new byte[_privateKey.Length];
		_extract(Id, first);
		_extract(Id, second);
		_extract("bob@example.com"u8, other);

		SelfTestException.ThrowIfNotEqual(first, second, "Two extractions for the same ID gave different keys.");
		SelfTestException.ThrowIfFalse(!first.AsSpan().SequenceEqual(other), "Two IDs got the same key.");
	}

	public override void Run(long iterations)
	{
		KeyExtractor extract = _extract;
		ReadOnlySpan<byte> id = Id;
		Span<byte> privateKey = _privateKey;

		for (long i = 0; i < iterations; ++i)
		{
			extract(id, privateKey);
		}
	}

	public override void Dispose()
	{
		_master.Dispose();
	}
}
