namespace CryptoBase.SpeedTest.Workloads;

/// <summary>
/// One operation of one algorithm on fixed inputs, prepared for timing.
/// </summary>
/// <remarks>
/// The hot loop lives in <see cref="Run" />, so the timer calls it once per batch rather than once per operation.
/// A throughput workload processes the same input size on every iteration; an operation workload performs one operation per iteration.
/// An instance is used by one thread at a time.
/// A workload generic over the algorithm runs its loop in a generic method of its own type parameter rather than in <see cref="Run" />:
/// Native AOT compiles one copy of a generic class for all reference types, which finds the methods of the algorithm through the dictionary
/// of the class on every iteration, at several nanoseconds per call, while a generic method finds them through its own at a fraction of that.
/// </remarks>
internal abstract class Workload : IDisposable
{
	/// <summary>
	/// Checks once, before timing, that the operation gives the expected result, such as a round trip or an agreed secret.
	/// </summary>
	/// <exception cref="SelfTestException">The check failed.</exception>
	public abstract void Verify();

	/// <summary>
	/// Performs the operation <paramref name="iterations" /> times.
	/// </summary>
	/// <exception cref="SelfTestException">An operation reported failure, such as a rejected tag.</exception>
	public abstract void Run(long iterations);

	public virtual void Dispose()
	{
	}
}
