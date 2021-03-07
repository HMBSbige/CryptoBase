using System;

namespace CryptoBase.Abstractions.Digests
{
	/// <summary>
	/// 摘要算法接口
	/// </summary>
	public interface IHash : ICanReset
	{
		/// <summary>
		/// 算法名
		/// </summary>
		string Name { get; }

		/// <summary>
		/// Hash 长度
		/// </summary>
		int Length { get; }

		void UpdateFinal(ReadOnlySpan<byte> origin, Span<byte> destination);

		void Update(ReadOnlySpan<byte> source);

		void GetHash(Span<byte> destination);
	}
}
