namespace CryptoBase.SpeedTest.Catalog;

/// <summary>
/// Lists every algorithm the tool measures. Each category lives in its own partial file; adding an algorithm takes one line there.
/// </summary>
internal static partial class AlgorithmCatalog
{
	public static ImmutableArray<AlgorithmEntry> Entries { get; } = Validate
	(
		[
			.. CreateHashEntries(),
			.. CreateXofEntries(),
			.. CreateMacEntries(),
			.. CreateStreamEntries(),
			.. CreateBlockEntries(),
			.. CreateAeadEntries(),
			.. CreateXtsEntries(),
			.. CreateSignatureEntries(),
			.. CreatePublicKeyEncryptionEntries(),
			.. CreateKemEntries(),
			.. CreateKeyAgreementEntries(),
			.. CreateKdfEntries()
		]
	);

	private static ImmutableArray<AlgorithmEntry> Validate(ImmutableArray<AlgorithmEntry> entries)
	{
		HashSet<string> names = new(StringComparer.OrdinalIgnoreCase) { AlgorithmSelector.AllSelector };

		foreach (AlgorithmGroup group in AlgorithmGroups.All)
		{
			names.Add(group.Name);
		}

		foreach (AlgorithmEntry entry in entries)
		{
			if (!names.Add(entry.Name) || entry.Name != entry.Name.ToLowerInvariant() || entry.Operations.IsDefaultOrEmpty || entry.Operations.Distinct().Count() != entry.Operations.Length)
			{
				throw new InvalidOperationException($"The catalog entry '{entry.Name}' is invalid or its name is taken.");
			}

			// The columns of an operation group are its operations, so an entry cannot have another.
			if (entry.Metric is Metric.Operations && !entry.Operations.All(entry.Group.Operations.Contains))
			{
				throw new InvalidOperationException($"The catalog entry '{entry.Name}' is invalid or its name is taken.");
			}
		}

		return [.. entries.OrderBy(entry => AlgorithmGroups.All.IndexOf(entry.Group))];
	}

	private static AlgorithmEntry Hash<T>(string name) where T : class, IHashAlgorithm<T>
	{
		return new AlgorithmEntry
		{
			Name = name,
			Group = AlgorithmGroups.Hash,
			ImplementationType = typeof(T),
			Operations = [OperationNames.Hash],
			CreateWorkload = static (_, inputSize) => new HashWorkload<T>(inputSize)
		};
	}

	private static AlgorithmEntry Xof<T>(string name, int outputLength) where T : class, IXof<T>
	{
		return new AlgorithmEntry
		{
			Name = name,
			Group = AlgorithmGroups.Xof,
			ImplementationType = typeof(T),
			Operations = [OperationNames.Hash],
			CreateWorkload = (_, inputSize) => new XofWorkload<T>(inputSize, outputLength)
		};
	}

	private static AlgorithmEntry Mac<T>(string name, int keySize) where T : IOneShotMacAlgorithm
	{
		return new AlgorithmEntry
		{
			Name = name,
			Group = AlgorithmGroups.Mac,
			ImplementationType = typeof(T),
			Operations = [OperationNames.Mac],
			CreateWorkload = (_, inputSize) => new MacWorkload<T>(inputSize, keySize)
		};
	}

	/// <summary>
	/// Creates an entry for a MAC that only a static method of <typeparamref name="T" /> other than <see cref="IOneShotMacAlgorithm.Mac" /> computes.
	/// </summary>
	private static AlgorithmEntry Mac<T>(string name, int keySize, int macLength, MacFunction function)
	{
		return new AlgorithmEntry
		{
			Name = name,
			Group = AlgorithmGroups.Mac,
			ImplementationType = typeof(T),
			Operations = [OperationNames.Mac],
			CreateWorkload = (_, inputSize) => new MacFunctionWorkload(inputSize, keySize, macLength, function)
		};
	}

	private static AlgorithmEntry Stream<T>(string name, Func<T> factory) where T : class, IStreamCipher
	{
		return new AlgorithmEntry
		{
			Name = name,
			Group = AlgorithmGroups.Stream,
			ImplementationType = typeof(T),
			Operations = [OperationNames.Xor],
			CreateWorkload = (_, inputSize) => new StreamWorkload<T>(inputSize, factory)
		};
	}

	private static AlgorithmEntry Block<T>(string name, int keySize) where T : IBlockCipher<T>
	{
		return new AlgorithmEntry
		{
			Name = name,
			Group = AlgorithmGroups.Block,
			ImplementationType = typeof(T),
			Operations = [OperationNames.Encrypt, OperationNames.Decrypt],
			MinimumInputSize = T.BlockSize,
			InputSizeMultiple = T.BlockSize,
			CreateWorkload = (operation, inputSize) => new BlockWorkload<T>(inputSize, keySize, IsDecrypt(operation))
		};
	}

	private static AlgorithmEntry Aead<T>(string name, int keySize, int maximumInputSize = int.MaxValue) where T : IAeadCipher<T>
	{
		return new AlgorithmEntry
		{
			Name = name,
			Group = AlgorithmGroups.Aead,
			ImplementationType = typeof(T),
			Operations = [OperationNames.Encrypt, OperationNames.Decrypt],
			MaximumInputSize = maximumInputSize,
			CreateWorkload = (operation, inputSize) => new AeadWorkload<T>(inputSize, keySize, IsDecrypt(operation))
		};
	}

	/// <summary>
	/// Creates an entry for a chunked cipher that measures whole messages with its one-shot methods.
	/// </summary>
	private static AlgorithmEntry ChunkedMessage<T>(string name, MessageEncryptor encrypt, MessageDecryptor tryDecrypt) where T : IChunkedCipher<T>
	{
		return new AlgorithmEntry
		{
			Name = name,
			Group = AlgorithmGroups.Aead,
			ImplementationType = typeof(T),
			Operations = [OperationNames.Encrypt, OperationNames.Decrypt],
			CreateWorkload = (operation, inputSize) => new ChunkedMessageWorkload<T>(inputSize, encrypt, tryDecrypt, IsDecrypt(operation))
		};
	}

	private static AlgorithmEntry DataUnit<T>(string name, int keySize, int minimumInputSize) where T : IDataUnitCipher<T>
	{
		return new AlgorithmEntry
		{
			Name = name,
			Group = AlgorithmGroups.Xts,
			ImplementationType = typeof(T),
			Operations = [OperationNames.Encrypt, OperationNames.Decrypt],
			MinimumInputSize = minimumInputSize,
			CreateWorkload = (operation, inputSize) => new DataUnitWorkload<T>(inputSize, keySize, IsDecrypt(operation))
		};
	}

	private static AlgorithmEntry Kem<T>(string name) where T : class, IKem<T>
	{
		return new AlgorithmEntry
		{
			Name = name,
			Group = AlgorithmGroups.Kem,
			ImplementationType = typeof(T),
			Operations = [OperationNames.KeyGen, OperationNames.Encapsulate, OperationNames.Decapsulate],
			CreateWorkload = static (operation, _) => new KemWorkload<T>
			(
				operation switch
				{
					OperationNames.KeyGen => KemOperation.KeyGen,
					OperationNames.Encapsulate => KemOperation.Encapsulate,
					OperationNames.Decapsulate => KemOperation.Decapsulate,
					_ => throw new ArgumentOutOfRangeException(nameof(operation), operation, null)
				}
			)
		};
	}

	private static AlgorithmEntry KeyAgreement<T>(string name) where T : class, IKeyAgreement<T>
	{
		return new AlgorithmEntry
		{
			Name = name,
			Group = AlgorithmGroups.Kex,
			ImplementationType = typeof(T),
			Operations = [OperationNames.KeyGen, OperationNames.Derive],
			CreateWorkload = static (operation, _) => new KeyAgreementWorkload<T>
			(
				operation switch
				{
					OperationNames.KeyGen => KeyAgreementOperation.KeyGen,
					OperationNames.Derive => KeyAgreementOperation.Derive,
					_ => throw new ArgumentOutOfRangeException(nameof(operation), operation, null)
				}
			)
		};
	}

	private static bool IsDecrypt(string operation)
	{
		return operation switch
		{
			OperationNames.Encrypt => false,
			OperationNames.Decrypt => true,
			_ => throw new ArgumentOutOfRangeException(nameof(operation), operation, null)
		};
	}
}
