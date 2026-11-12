namespace CryptoBase.SpeedTest.Catalog;

/// <summary>
/// Creates the workload of one operation; <paramref name="inputSize" /> is the message size in bytes for a throughput entry and 0 otherwise.
/// </summary>
internal delegate Workload WorkloadFactory(string operation, int inputSize);

internal sealed class AlgorithmEntry
{
	public required string Name { get; init; }

	public required AlgorithmGroup Group { get; init; }

	/// <summary>
	/// Gets the public type of the core library that implements the algorithm, as a closed generic type where it is generic.
	/// </summary>
	public required Type ImplementationType { get; init; }

	/// <summary>
	/// Gets the other public types of the core library that the workload uses, such as the user key of an identity-based scheme beside its master key.
	/// </summary>
	public ImmutableArray<Type> RelatedTypes { get; init; } = [];

	/// <summary>
	/// Gets the operations that can be measured. A throughput entry measures the first one, or <see cref="OperationNames.Decrypt" /> when asked to and it has one; an operation entry measures them all.
	/// </summary>
	public required ImmutableArray<string> Operations { get; init; }

	/// <summary>
	/// Gets a value indicating whether the algorithm is too slow to run as part of <c>all</c> or of its group, so that it only runs when named or matched by a wildcard.
	/// </summary>
	public bool IsSlow { get; init; }

	/// <summary>
	/// Gets the fixed parameters of the workload that its name does not tell, for the <c>list</c> command, or <see langword="null" />.
	/// </summary>
	public string? Notes { get; init; }

	public int MinimumInputSize { get; init; }

	public int MaximumInputSize { get; init; } = int.MaxValue;

	/// <summary>
	/// Gets the number that every input size of a throughput entry must be a multiple of, such as the block size of ECB.
	/// </summary>
	public int InputSizeMultiple { get; init; } = 1;

	public required WorkloadFactory CreateWorkload { get; init; }

	public Metric Metric => Group.Metric;

	public bool SupportsInputSize(int inputSize)
	{
		return inputSize >= MinimumInputSize && inputSize <= MaximumInputSize && inputSize % InputSizeMultiple is 0;
	}

	public string GetThroughputOperation(bool decrypt)
	{
		return decrypt && Operations.Contains(OperationNames.Decrypt) ? OperationNames.Decrypt : Operations[0];
	}

	public override string ToString()
	{
		return Name;
	}
}
