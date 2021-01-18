using System;

namespace CryptoBase.Abstractions.Digests
{
	/// <summary>
	/// 摘要算法接口
	/// </summary>
	public interface IHash
	{
		/// <summary>
		/// 算法名
		/// </summary>
		string Name { get; }

		/// <summary>
		/// Hash 长度
		/// </summary>
		int Length { get; }

		/// <summary>
		/// 计算 Hash
		/// </summary>
		void Compute(in ReadOnlySpan<byte> origin, Span<byte> destination);
	}
}
