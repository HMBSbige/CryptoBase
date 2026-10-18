namespace CryptoBase.Kdf;

/// <summary>
/// Represents the cost parameters of Argon2, as specified by RFC 9106.
/// </summary>
public readonly record struct Argon2Parameters
{
	/// <summary>
	/// Initializes a new instance of the <see cref="Argon2Parameters" /> struct.
	/// </summary>
	/// <param name="memorySizeInKibibytes">
	/// The memory size m, in kibibytes. It must be at least 8 times <paramref name="parallelism" />.
	/// The memory used is m rounded down to a multiple of 4 times <paramref name="parallelism" /> kibibytes.
	/// </param>
	/// <param name="iterations">The number of passes t over the memory. It must be at least 1.</param>
	/// <param name="parallelism">The number of lanes p, from 1 to 2^24 - 1.</param>
	/// <exception cref="ArgumentOutOfRangeException">A parameter is outside its valid range.</exception>
	public Argon2Parameters(int memorySizeInKibibytes, int iterations, int parallelism)
	{
		ArgumentOutOfRangeException.ThrowIfLessThan(parallelism, 1);
		ArgumentOutOfRangeException.ThrowIfGreaterThan(parallelism, MaxParallelism);
		ArgumentOutOfRangeException.ThrowIfLessThan(iterations, 1);
		ArgumentOutOfRangeException.ThrowIfLessThan(memorySizeInKibibytes, 8 * parallelism);

		MemorySizeInKibibytes = memorySizeInKibibytes;
		Iterations = iterations;
		Parallelism = parallelism;
	}

	internal const int MaxParallelism = (1 << 24) - 1;

	/// <summary>
	/// Gets the first recommended option of RFC 9106 section 4: t = 1, p = 4, and m = 2 GiB.
	/// </summary>
	public static Argon2Parameters Rfc9106FirstRecommended => new(2 * 1024 * 1024, 1, 4);

	/// <summary>
	/// Gets the second recommended option of RFC 9106 section 4, for when much less memory is available: t = 3, p = 4, and m = 64 MiB.
	/// </summary>
	public static Argon2Parameters Rfc9106SecondRecommended => new(64 * 1024, 3, 4);

	/// <summary>
	/// Gets the memory size m, in kibibytes.
	/// </summary>
	public int MemorySizeInKibibytes { get; }

	/// <summary>
	/// Gets the number of passes t over the memory.
	/// </summary>
	public int Iterations { get; }

	/// <summary>
	/// Gets the number of lanes p.
	/// </summary>
	public int Parallelism { get; }
}
