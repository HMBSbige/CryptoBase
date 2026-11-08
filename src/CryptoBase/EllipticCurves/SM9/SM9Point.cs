namespace CryptoBase.EllipticCurves.SM9;

// A point (X : Y : Z) in homogeneous projective coordinates, x = X/Z and y = Y/Z, on the curve over TField; Z = 0 is the point at infinity, which SM9Curve gives as (0 : 1 : 0). Coordinates are reduced and in Montgomery form.
internal struct SM9Point<TField> where TField : unmanaged, ISM9Field<TField>
{
	internal TField X;
	internal TField Y;
	internal TField Z;
}

// A point (x, y) on the curve over TField, which cannot be the point at infinity. Coordinates are reduced and in Montgomery form.
internal struct SM9AffinePoint<TField> where TField : unmanaged, ISM9Field<TField>
{
	internal TField X;
	internal TField Y;
}
