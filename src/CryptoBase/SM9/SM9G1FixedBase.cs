using CryptoBase.EllipticCurves;
using CryptoBase.EllipticCurves.SM9;

namespace CryptoBase.SM9;

// A point Q of G1 that many products take, as the private key dsA of a signer and the encryption master public key Ppub-e do, with its table of SM9BaseTable from product TableThreshold on, so that a key that takes few products does not pay for the build. The count is atomic, so that products at once still reach the threshold, and it stops once the table is there; whether a product takes the table depends on the count alone.
// A secret Q, as dsA is, has a table as secret as it is: threads that reach the threshold at once may each build one, but only the first to finish publishes it and the others erase theirs, and Dispose erases Q and the table. The products with and without the table agree.
internal sealed class SM9G1FixedBase : IDisposable
{
	internal const int TableThreshold = 10;

	// Windows of width 5, 52 of 16 entries.
	private const int TableWidth = 5;

	private SM9AffinePoint<SM9Fp> _point;
	private readonly bool _secret;
	private SM9BaseTable<SM9Fp>? _table;
	private int _products;

	internal SM9G1FixedBase(in SM9AffinePoint<SM9Fp> point, bool secret)
	{
		_point = point;
		_secret = secret;
	}

	internal ref readonly SM9AffinePoint<SM9Fp> Point => ref _point;

	// k·Q for k in [1, N − 1]. Neither the time nor the addresses depend on k or Q.
	internal void Multiply(in FieldElement<SM9Order> scalar, out SM9AffinePoint<SM9Fp> result)
	{
		if (GetTable() is { } table)
		{
			SM9G1.Multiply(table, in scalar, out result);
		}
		else
		{
			SM9G1.Multiply(in _point, in scalar, out result);
		}
	}

	// a·P1 + b·Q, as SM9G1.MultiplyBaseSum gives it.
	internal ulong MultiplyBaseSum(in FieldElement<SM9Order> baseScalar, in FieldElement<SM9Order> scalar, out SM9AffinePoint<SM9Fp> result)
	{
		return SM9G1.MultiplyBaseSum(in baseScalar, in _point, GetTable(), in scalar, out result);
	}

	public void Dispose()
	{
		if (_secret)
		{
			_point.ZeroMemory();
			Interlocked.Exchange(ref _table, null)?.Clear();
		}
	}

	private SM9BaseTable<SM9Fp>? GetTable()
	{
		if (_table is { } table)
		{
			return table;
		}

		return Interlocked.Increment(ref _products) < TableThreshold ? null : PublishTable();
	}

	private SM9BaseTable<SM9Fp> PublishTable()
	{
		SM9BaseTable<SM9Fp> table = new(in _point, TableWidth, _secret);

		if (Interlocked.CompareExchange(ref _table, table, null) is { } published)
		{
			table.Clear();
			return published;
		}

		return table;
	}
}
