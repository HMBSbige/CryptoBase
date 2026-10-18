using CryptoBase.Kdf;
using CryptoBase.Kdf.Argon2;

namespace CryptoBase.Tests.Kdf.Argon2;

public abstract class Argon2KernelCase
{
	public static IEnumerable<Argon2KernelCase> All()
	{
		yield return new Kernel<Argon2Scalar>();
		yield return new Kernel<Argon2Vector128>();
		yield return new Kernel<Argon2AdvSimd>();
		yield return new Kernel<Argon2Vector256>();
		yield return new Kernel<Argon2Vector512>();
	}

	public abstract Type KernelType { get; }

	public abstract bool IsSupported { get; }

	internal abstract void Compress(ref Argon2Block previous, ref Argon2Block reference, ref Argon2Block destination, ref Argon2Block scratch, bool xorDestination);

	public abstract void DeriveKey(ReadOnlySpan<byte> password, ReadOnlySpan<byte> salt, ReadOnlySpan<byte> secret, ReadOnlySpan<byte> associatedData, Argon2Type type, Argon2Parameters parameters, Span<byte> destination);

	public override string ToString()
	{
		return KernelType.Name;
	}

	private sealed class Kernel<TKernel> : Argon2KernelCase where TKernel : IArgon2Kernel
	{
		public override Type KernelType => typeof(TKernel);

		public override bool IsSupported => TKernel.IsSupported;

		internal override void Compress(ref Argon2Block previous, ref Argon2Block reference, ref Argon2Block destination, ref Argon2Block scratch, bool xorDestination)
		{
			TKernel.Compress(ref previous, ref reference, ref destination, ref scratch, xorDestination);
		}

		public override void DeriveKey(ReadOnlySpan<byte> password, ReadOnlySpan<byte> salt, ReadOnlySpan<byte> secret, ReadOnlySpan<byte> associatedData, Argon2Type type, Argon2Parameters parameters, Span<byte> destination)
		{
			Argon2Core.DeriveKey<TKernel>(password, salt, secret, associatedData, type, parameters, -1, destination);
		}
	}
}
