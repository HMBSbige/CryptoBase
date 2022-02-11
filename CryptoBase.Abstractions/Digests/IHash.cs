namespace CryptoBase.Abstractions.Digests;

/// <summary>
/// 摘要算法接口
/// </summary>
public interface IHash : ICanReset, IDisposable
{
	/// <summary>
	/// 算法名
	/// </summary>
	string Name { get; }

	/// <summary>
	/// Hash 输出长度
	/// </summary>
	int Length { get; }

	/// <summary>
	/// 块大小
	/// </summary>
	int BlockSize { get; }

	void UpdateFinal(ReadOnlySpan<byte> origin, Span<byte> destination);

	void Update(ReadOnlySpan<byte> source);

	void GetHash(Span<byte> destination);
}
