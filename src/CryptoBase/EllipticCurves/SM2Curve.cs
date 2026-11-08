namespace CryptoBase.EllipticCurves;

// The recommended curve of GB/T 32918.5, with a = p − 3.
internal readonly struct SM2Curve : IECCurve
{
	public static ReadOnlySpan<ulong> B =>
	[
		0xDDBCBD414D940E93UL, 0xF39789F515AB8F92UL, 0x4D5A9E4BCF6509A7UL, 0x28E9FA9E9D9F5E34UL,
	];

	public static ReadOnlySpan<ulong> GeneratorX =>
	[
		0x715A4589334C74C7UL, 0x8FE30BBFF2660BE1UL, 0x5F9904466A39C994UL, 0x32C4AE2C1F198119UL,
	];

	public static ReadOnlySpan<ulong> GeneratorY =>
	[
		0x02DF32E52139F0A0UL, 0xD0A9877CC62A4740UL, 0x59BDCEE36B692153UL, 0xBC3736A2F4F6779CUL,
	];

	// For the products of secret scalars, which scan every entry of a window, so narrower than those of SM2VerificationCurve for public scalars; the top window starts at bit 252.
	public static int GeneratorWindowWidth => 6;

	public static bool HasMultiplyAdd => SM2KernelDispatch.HasMultiplyAdd;

	// The products of SM2KernelDispatch, for the field and the order of SM2, which are the only ones that ECGroup takes with this curve.
	public static bool TryMultiplyBase<TField, TOrder>(in FieldElement<TOrder> scalar, out JacobianPoint<TField> result) where TField : unmanaged, IECField<TField> where TOrder : unmanaged, IMontgomeryModulus
	{
		Unsafe.SkipInit(out result);

		if (typeof(TField) != typeof(SM2CurveField) || typeof(TOrder) != typeof(SM2Order))
		{
			return false;
		}

		SM2KernelDispatch.MultiplyBase(in Unsafe.As<FieldElement<TOrder>, FieldElement<SM2Order>>(ref Unsafe.AsRef(in scalar)), out Unsafe.As<JacobianPoint<TField>, JacobianPoint<SM2CurveField>>(ref result));
		return true;
	}

	public static bool TryMultiplyAdd<TField, TOrder>(in FieldElement<TOrder> u1, ReadOnlySpan<AffinePoint<TField>> pointTable, in FieldElement<TOrder> u2, out JacobianPoint<TField> result) where TField : unmanaged, IECField<TField> where TOrder : unmanaged, IMontgomeryModulus
	{
		Unsafe.SkipInit(out result);

		if (typeof(TField) != typeof(SM2CurveField) || typeof(TOrder) != typeof(SM2Order))
		{
			return false;
		}

		ReadOnlySpan<AffinePoint<SM2CurveField>> table = MemoryMarshal.Cast<AffinePoint<TField>, AffinePoint<SM2CurveField>>(pointTable);
		SM2KernelDispatch.MultiplyAdd(in Unsafe.As<FieldElement<TOrder>, FieldElement<SM2Order>>(ref Unsafe.AsRef(in u1)), table, in Unsafe.As<FieldElement<TOrder>, FieldElement<SM2Order>>(ref Unsafe.AsRef(in u2)), out Unsafe.As<JacobianPoint<TField>, JacobianPoint<SM2CurveField>>(ref result));
		return true;
	}

	public static bool TryFillBases<TField, TOrder>(in AffinePoint<TField> point, Span<JacobianPoint<TField>> bases) where TField : unmanaged, IECField<TField> where TOrder : unmanaged, IMontgomeryModulus
	{
		if (typeof(TField) != typeof(SM2CurveField) || typeof(TOrder) != typeof(SM2Order))
		{
			return false;
		}

		SM2KernelDispatch.FillBases<SM2Curve>(in Unsafe.As<AffinePoint<TField>, AffinePoint<SM2CurveField>>(ref Unsafe.AsRef(in point)), MemoryMarshal.Cast<JacobianPoint<TField>, JacobianPoint<SM2CurveField>>(bases));
		return true;
	}

	public static bool TryFillWindows<TField, TOrder>(Span<ulong> windows) where TField : unmanaged, IECField<TField> where TOrder : unmanaged, IMontgomeryModulus
	{
		if (typeof(TField) != typeof(SM2CurveField) || typeof(TOrder) != typeof(SM2Order))
		{
			return false;
		}

		SM2KernelDispatch.FillWindows<SM2Curve>(windows);
		return true;
	}

	public static bool TryMultiplyFixed<TField, TOrder>(ReadOnlySpan<ulong> windows, in FieldElement<TOrder> scalar, out JacobianPoint<TField> result) where TField : unmanaged, IECField<TField> where TOrder : unmanaged, IMontgomeryModulus
	{
		Unsafe.SkipInit(out result);

		if (typeof(TField) != typeof(SM2CurveField) || typeof(TOrder) != typeof(SM2Order))
		{
			return false;
		}

		SM2KernelDispatch.MultiplyFixed(windows, in Unsafe.As<FieldElement<TOrder>, FieldElement<SM2Order>>(ref Unsafe.AsRef(in scalar)), out Unsafe.As<JacobianPoint<TField>, JacobianPoint<SM2CurveField>>(ref result));
		return true;
	}

	public static bool TryMultiplyBaseAndFixed<TField, TOrder>(ReadOnlySpan<ulong> windows, in FieldElement<TOrder> scalar, out JacobianPoint<TField> baseResult, out JacobianPoint<TField> result) where TField : unmanaged, IECField<TField> where TOrder : unmanaged, IMontgomeryModulus
	{
		Unsafe.SkipInit(out baseResult);
		Unsafe.SkipInit(out result);

		if (typeof(TField) != typeof(SM2CurveField) || typeof(TOrder) != typeof(SM2Order))
		{
			return false;
		}

		SM2KernelDispatch.MultiplyBaseAndFixed(windows, in Unsafe.As<FieldElement<TOrder>, FieldElement<SM2Order>>(ref Unsafe.AsRef(in scalar)), out Unsafe.As<JacobianPoint<TField>, JacobianPoint<SM2CurveField>>(ref baseResult), out Unsafe.As<JacobianPoint<TField>, JacobianPoint<SM2CurveField>>(ref result));
		return true;
	}

	public static bool TryMultiply<TField, TOrder>(in AffinePoint<TField> point, in FieldElement<TOrder> scalar, out JacobianPoint<TField> result) where TField : unmanaged, IECField<TField> where TOrder : unmanaged, IMontgomeryModulus
	{
		Unsafe.SkipInit(out result);

		if (typeof(TField) != typeof(SM2CurveField) || typeof(TOrder) != typeof(SM2Order))
		{
			return false;
		}

		SM2KernelDispatch.Multiply(in Unsafe.As<AffinePoint<TField>, AffinePoint<SM2CurveField>>(ref Unsafe.AsRef(in point)), in Unsafe.As<FieldElement<TOrder>, FieldElement<SM2Order>>(ref Unsafe.AsRef(in scalar)), out Unsafe.As<JacobianPoint<TField>, JacobianPoint<SM2CurveField>>(ref result));
		return true;
	}

	public static bool TryMultiplyAdd<TField, TOrder>(in FieldElement<TOrder> u1, in AffinePoint<TField> point, in FieldElement<TOrder> u2, out JacobianPoint<TField> result) where TField : unmanaged, IECField<TField> where TOrder : unmanaged, IMontgomeryModulus
	{
		Unsafe.SkipInit(out result);

		if (typeof(TField) != typeof(SM2CurveField) || typeof(TOrder) != typeof(SM2Order))
		{
			return false;
		}

		SM2KernelDispatch.MultiplyAdd(in Unsafe.As<FieldElement<TOrder>, FieldElement<SM2Order>>(ref Unsafe.AsRef(in u1)), in Unsafe.As<AffinePoint<TField>, AffinePoint<SM2CurveField>>(ref Unsafe.AsRef(in point)), in Unsafe.As<FieldElement<TOrder>, FieldElement<SM2Order>>(ref Unsafe.AsRef(in u2)), out Unsafe.As<JacobianPoint<TField>, JacobianPoint<SM2CurveField>>(ref result));
		return true;
	}

	public static bool TryMultiplyAddXModOrderEquals<TField, TOrder>(in FieldElement<TOrder> u1, in AffinePoint<TField> point, in FieldElement<TOrder> u2, in FieldElement<TOrder> r, out bool equals) where TField : unmanaged, IECField<TField> where TOrder : unmanaged, IMontgomeryModulus
	{
		if (typeof(TField) != typeof(SM2CurveField) || typeof(TOrder) != typeof(SM2Order) || !SM2KernelDispatch.HasMultiplyAddXModOrderEquals)
		{
			equals = false;
			return false;
		}

		equals = SM2KernelDispatch.MultiplyAddXModOrderEquals(in Unsafe.As<FieldElement<TOrder>, FieldElement<SM2Order>>(ref Unsafe.AsRef(in u1)), in Unsafe.As<AffinePoint<TField>, AffinePoint<SM2CurveField>>(ref Unsafe.AsRef(in point)), in Unsafe.As<FieldElement<TOrder>, FieldElement<SM2Order>>(ref Unsafe.AsRef(in u2)), in Unsafe.As<FieldElement<TOrder>, FieldElement<SM2Order>>(ref Unsafe.AsRef(in r)));
		return true;
	}

	public static bool TryMultiplyAdd<TField, TOrder>(in AffinePoint<TField> point, in FieldElement<TOrder> scalar, in AffinePoint<TField> otherPoint, in FieldElement<TOrder> otherScalar, out JacobianPoint<TField> result) where TField : unmanaged, IECField<TField> where TOrder : unmanaged, IMontgomeryModulus
	{
		Unsafe.SkipInit(out result);

		if (typeof(TField) != typeof(SM2CurveField) || typeof(TOrder) != typeof(SM2Order) || !SM2KernelDispatch.HasMultiplyAdd)
		{
			return false;
		}

		SM2KernelDispatch.MultiplyAdd(in Unsafe.As<AffinePoint<TField>, AffinePoint<SM2CurveField>>(ref Unsafe.AsRef(in point)), in Unsafe.As<FieldElement<TOrder>, FieldElement<SM2Order>>(ref Unsafe.AsRef(in scalar)), in Unsafe.As<AffinePoint<TField>, AffinePoint<SM2CurveField>>(ref Unsafe.AsRef(in otherPoint)), in Unsafe.As<FieldElement<TOrder>, FieldElement<SM2Order>>(ref Unsafe.AsRef(in otherScalar)), out Unsafe.As<JacobianPoint<TField>, JacobianPoint<SM2CurveField>>(ref result));
		return true;
	}
}
