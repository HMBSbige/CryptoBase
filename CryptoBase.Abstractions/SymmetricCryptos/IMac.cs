using System;

namespace CryptoBase.Abstractions.SymmetricCryptos
{
	public interface IMac : IDisposable, ICanReset
	{
		/// <summary>
		/// 算法名
		/// </summary>
		string Name { get; }

		void Update(ReadOnlySpan<byte> source);

		void GetMac(Span<byte> destination);
	}
}
