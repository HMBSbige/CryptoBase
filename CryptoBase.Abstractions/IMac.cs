using System;

namespace CryptoBase.Abstractions
{
	public interface IMac : IDisposable, ICanReset
	{
		/// <summary>
		/// 算法名
		/// </summary>
		string Name { get; }

		/// <summary>
		/// Mac 输出长度
		/// </summary>
		int Length { get; }

		void Update(ReadOnlySpan<byte> source);

		void GetMac(Span<byte> destination);
	}
}
