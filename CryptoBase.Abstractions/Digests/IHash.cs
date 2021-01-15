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
		/// 计算 Hash
		/// </summary>
		Span<byte> Compute(in ReadOnlySpan<byte> origin);
	}
}
