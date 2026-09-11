namespace CryptoBase.Hashes.Crc32;

internal readonly struct Crc32X86FoldingConstants
{
	internal Crc32X86FoldingConstants(ulong fold2048Lower, ulong fold2048Upper, ulong fold1024Lower, ulong fold1024Upper, ulong fold512Lower, ulong fold512Upper, ulong fold256Lower, ulong fold256Upper, ulong fold128Lower, ulong fold128Upper)
	{
		Fold2048Vector512 = Vector512.Create(fold2048Lower, fold2048Upper, fold2048Lower, fold2048Upper, fold2048Lower, fold2048Upper, fold2048Lower, fold2048Upper);
		Fold1024Vector512 = Vector512.Create(fold1024Lower, fold1024Upper, fold1024Lower, fold1024Upper, fold1024Lower, fold1024Upper, fold1024Lower, fold1024Upper);
		Fold512Vector512 = Vector512.Create(fold512Lower, fold512Upper, fold512Lower, fold512Upper, fold512Lower, fold512Upper, fold512Lower, fold512Upper);
		Fold2048Vector256 = Vector256.Create(fold2048Lower, fold2048Upper, fold2048Lower, fold2048Upper);
		Fold1024Vector256 = Vector256.Create(fold1024Lower, fold1024Upper, fold1024Lower, fold1024Upper);
		Fold512Vector256 = Vector256.Create(fold512Lower, fold512Upper, fold512Lower, fold512Upper);
		Fold256Vector256 = Vector256.Create(fold256Lower, fold256Upper, fold256Lower, fold256Upper);
		Fold512Vector128 = Vector128.Create(fold512Lower, fold512Upper);
		Fold128Vector128 = Vector128.Create(fold128Lower, fold128Upper);
	}

	internal Vector512<ulong> Fold2048Vector512 { get; }

	internal Vector512<ulong> Fold1024Vector512 { get; }

	internal Vector512<ulong> Fold512Vector512 { get; }

	internal Vector256<ulong> Fold2048Vector256 { get; }

	internal Vector256<ulong> Fold1024Vector256 { get; }

	internal Vector256<ulong> Fold512Vector256 { get; }

	internal Vector256<ulong> Fold256Vector256 { get; }

	internal Vector128<ulong> Fold512Vector128 { get; }

	internal Vector128<ulong> Fold128Vector128 { get; }
}
