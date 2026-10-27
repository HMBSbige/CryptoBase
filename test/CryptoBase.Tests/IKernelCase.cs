namespace CryptoBase.Tests;

// A kernel under test, named by ToString.
public interface IKernelCase
{
	bool IsSupported { get; }
}
