using System;

namespace CryptoBase.Abstractions.SymmetricCryptos
{
	public abstract class StreamCryptoBase : IStreamCrypto
	{
		public abstract string Name { get; }

		public virtual void Update(ReadOnlySpan<byte> source, Span<byte> destination)
		{
			if (destination.Length < source.Length)
			{
				throw new ArgumentException(string.Empty, nameof(destination));
			}
		}

		public abstract void Reset();

		public virtual void Dispose() { }
	}
}
