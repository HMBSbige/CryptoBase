namespace CryptoBase.SpeedTest.Catalog;

internal enum Metric
{
	/// <summary>Bytes of input per second, one column per input size.</summary>
	Throughput,

	/// <summary>Operations per second, one column per operation.</summary>
	Operations
}

/// <param name="Operations">The operations of an operation group in the order of its columns, or none for a throughput group, whose columns are input sizes.</param>
internal sealed record AlgorithmGroup(string Name, Metric Metric, string Description, ImmutableArray<string> Operations);

internal static class AlgorithmGroups
{
	public static readonly AlgorithmGroup Hash = new("hash", Metric.Throughput, "Hash functions", []);
	public static readonly AlgorithmGroup Xof = new("xof", Metric.Throughput, "Extendable-output functions", []);
	public static readonly AlgorithmGroup Mac = new("mac", Metric.Throughput, "Message authentication codes", []);
	public static readonly AlgorithmGroup Stream = new("stream", Metric.Throughput, "Stream ciphers", []);
	public static readonly AlgorithmGroup Block = new("block", Metric.Throughput, "Block ciphers on whole blocks (ECB)", []);
	public static readonly AlgorithmGroup Aead = new("aead", Metric.Throughput, "Authenticated encryption", []);
	public static readonly AlgorithmGroup Xts = new("xts", Metric.Throughput, "Data-unit (disk) encryption", []);
	public static readonly AlgorithmGroup Sign = new("sign", Metric.Operations, "Digital signatures", [OperationNames.KeyGen, OperationNames.Sign, OperationNames.Verify]);
	public static readonly AlgorithmGroup Pke = new("pke", Metric.Operations, "Public key encryption", [OperationNames.Encrypt, OperationNames.Decrypt]);
	public static readonly AlgorithmGroup Kem = new("kem", Metric.Operations, "Key encapsulation", [OperationNames.KeyGen, OperationNames.Encapsulate, OperationNames.Decapsulate]);
	public static readonly AlgorithmGroup Kex = new("kex", Metric.Operations, "Key agreement", [OperationNames.KeyGen, OperationNames.Derive]);
	public static readonly AlgorithmGroup Kdf = new("kdf", Metric.Operations, "Key derivation", [OperationNames.Derive]);

	/// <summary>
	/// Gets the groups in the order in which they run and are reported.
	/// </summary>
	public static ImmutableArray<AlgorithmGroup> All { get; } = [Hash, Xof, Mac, Stream, Block, Aead, Xts, Sign, Pke, Kem, Kex, Kdf];
}

internal static class OperationNames
{
	public const string Hash = "hash";
	public const string Mac = "mac";
	public const string Xor = "xor";
	public const string Encrypt = "encrypt";
	public const string Decrypt = "decrypt";
	public const string KeyGen = "keygen";
	public const string Encapsulate = "encaps";
	public const string Decapsulate = "decaps";
	public const string Derive = "derive";
	public const string Sign = "sign";
	public const string Verify = "verify";
}
