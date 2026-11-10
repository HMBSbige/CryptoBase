namespace CryptoBase.EllipticCurves.SM9;

// ISM9FieldLanes on the rows of SM9Lanes, for the points of G1 over FpLanes and those of G2 over Fp2Lanes, and the shuffles of the formulas of SM9PointLanes on one point. The products are the lane products of AccumulateLanes, reduced by Reduce1 and Reduce2. A member that takes vectors works on that many vectors of each row from vector 0, which hold the lanes it needs; the others work on vector 0.
internal static partial class SM9Lanes<TVector>
{
	// The patterns of MoveDown: lane i takes lane i + d, the last lanes taking lanes of the row again.
	private const ulong DownOne = 0x77654321;

	private const ulong DownTwo = 0x76765432;

	private const ulong DownFour = 0x76547654;

	// An element of Fp in each lane, ten rows.
	internal readonly struct FpLanes : ISM9FieldLanes<SM9Fp>
	{
		public static int ElementLength => ComponentLength;

		public static int ColumnsLength => WideLength;

		public static int ScratchLength => 0;

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public static void Split(in SM9Fp value, ref ulong rows, int lane)
		{
			SM9Lanes<TVector>.Split(in value, ref Unsafe.Add(ref rows, lane));
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public static void Join(ref ulong rows, int lane, out SM9Fp result)
		{
			SM9Lanes<TVector>.Join(ref Unsafe.Add(ref rows, lane), out result);
		}

		public static void One(ref ulong result)
		{
			for (int lane = 0; lane < RowLength; ++lane)
			{
				SM9Lanes<TVector>.Split(in SM9Fp.One, ref Unsafe.Add(ref result, lane));
			}
		}

		public static void Clear(ref ulong result)
		{
			Unsafe.InitBlockUnaligned(ref Unsafe.As<ulong, byte>(ref result), 0, ComponentLength * sizeof(ulong));
		}

		// Limbs below 2^31 and 2^27, the most that the formulas take, keep each column of ten products below 2^61.4; column 19 of a lane product is 0.
		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public static void Multiply(ref ulong left, ref ulong right, ref ulong columns, ref ulong scratch, int vectors)
		{
			for (int v = 0; v < vectors; ++v)
			{
				AccumulateLanes(ref left, ref right, v, ref columns);
				TVector.Zero.Store(ref Unsafe.Add(ref columns, RowLength * (WideRows - 1) + v * TVector.Count));
			}
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public static void SubtractColumns(ref ulong columns, ref ulong subtrahend)
		{
			SubtractColumnRows(ref columns, ref subtrahend);
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public static void AddColumns(ref ulong columns, ref ulong addend)
		{
			AddColumnRows(ref columns, ref addend);
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public static void AddShifted(ref ulong columns, ref ulong value)
		{
			AddLaneRows(ref Unsafe.Add(ref columns, ComponentLength), ref value, ref Unsafe.Add(ref columns, ComponentLength), LimbCount, 1);
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public static void Reduce(ref ulong columns, ref ulong result, int vectors)
		{
			for (int v = 0; v < vectors; ++v)
			{
				Reduce1(ref Unsafe.Add(ref columns, v * TVector.Count), ref Unsafe.Add(ref result, v * TVector.Count));
			}
		}

		// The rounds of the reduction go between the rows of the product, which leaves the columns unwritten.
		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public static void MultiplyReduce(ref ulong left, ref ulong right, ref ulong result, ref ulong columns, ref ulong scratch, int vectors)
		{
			for (int v = 0; v < vectors; ++v)
			{
				MultiplyReduceLanes(ref left, ref right, v, ref result);
			}
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		static void ISM9FieldLanes<SM9Fp>.Reduce2(ref ulong columns, ref ulong otherColumns, ref ulong result, ref ulong otherResult)
		{
			SM9Lanes<TVector>.Reduce2(ref columns, ref otherColumns, ref result, ref otherResult);
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public static void Add(ref ulong left, ref ulong right, ref ulong result)
		{
			AddLaneRows(ref left, ref right, ref result, LimbCount, 1);
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public static void Triple(ref ulong value, ref ulong result)
		{
			TripleLaneRows(ref value, ref result, LimbCount);
		}

		// 15·value is below 15.0015p, which WeakReduce takes.
		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public static void MultiplyByThreeB(ref ulong value, ref ulong result, int vectors)
		{
			for (int v = 0; v < vectors; ++v)
			{
				FifteenLaneRows(ref Unsafe.Add(ref value, v * TVector.Count), ref Unsafe.Add(ref result, v * TVector.Count));
			}
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public static void WeakReduce(ref ulong value, int vectors)
		{
			for (int v = 0; v < vectors; ++v)
			{
				WeakReduceLaneRows(ref Unsafe.Add(ref value, v * TVector.Count));
			}
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public static void SubtractFromCover(ref ulong left, ref ulong right, ref ulong result)
		{
			SubtractFromCoverLaneRows(ref left, ref right, ref result, LimbCount);
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public static void SubtractTwo(ref ulong value, ref ulong first, ref ulong second, ref ulong result)
		{
			SubtractTwoLaneRows(ref value, ref first, ref second, ref result);
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public static void ConditionalSelect(ref ulong mask, ref ulong whenSet, ref ulong whenClear, ref ulong result, int vectors)
		{
			SelectLaneRows(ref mask, ref whenSet, ref whenClear, ref result, LimbCount, vectors);
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public static void ConditionalNegate(ref ulong mask, ref ulong value)
		{
			NegateLaneRows(ref mask, ref value, LimbCount);
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public static void MoveDown(ref ulong value, int distance, ref ulong result)
		{
			MoveDownLaneRows(ref value, distance, ref result, LimbCount);
		}

		// 3b = 15 goes into lane 2 of the right operand.
		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public static void DoublingOperands(ref ulong point, ref ulong left, ref ulong right, int vectors)
		{
			SM9Lanes<TVector>.DoublingOperands(ref point, ref left, ref right, LimbCount, true, vectors);
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public static void ThreeBLaneTwo(ref ulong value, ref ulong scratch, int vectors)
		{
		}
	}

	// An element of Fp2 in each lane, its real part in rows 0 to 9 and its u-part in rows 10 to 19. A product takes P0 = x0·y0, P1 = x1·y1 and Ps = (x0 + x1)(y0 + y1) into c0 = P0 − 2P1 + 128p² and c1 = Ps − P0 − P1, as u² = −2; columns hold c0 and then c1, and the scratch the sums x0 + x1 and y0 + y1 and then Ps.
	internal readonly struct Fp2Lanes : ISM9FieldLanes<SM9Fp2>
	{
		public static int ElementLength => 2 * ComponentLength;

		public static int ColumnsLength => 2 * WideLength;

		public static int ScratchLength => 2 * ComponentLength + WideLength;

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		static void ISM9FieldLanes<SM9Fp2>.Split(in SM9Fp2 value, ref ulong rows, int lane)
		{
			SM9Lanes<TVector>.Split(in value, ref rows, lane);
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		static void ISM9FieldLanes<SM9Fp2>.Join(ref ulong rows, int lane, out SM9Fp2 result)
		{
			SM9Lanes<TVector>.Join(ref rows, lane, out result);
		}

		public static void One(ref ulong result)
		{
			FpLanes.One(ref result);
			FpLanes.Clear(ref Unsafe.Add(ref result, ComponentLength));
		}

		public static void Clear(ref ulong result)
		{
			Unsafe.InitBlockUnaligned(ref Unsafe.As<ulong, byte>(ref result), 0, 2 * ComponentLength * sizeof(ulong));
		}

		// For components with limbs below 2^29 and 2^28, or 2^30 and 2^27, and sums below 2^30 and 2^29 or 2^31 and 2^28, the columns of P0 and P1 are below 2^60.4 and those of Ps below 2^62.4, so c0 and c1 stay below 2^62.5 in magnitude.
		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public static void Multiply(ref ulong left, ref ulong right, ref ulong columns, ref ulong scratch, int vectors)
		{
			ref ulong leftSum = ref scratch;
			ref ulong rightSum = ref Unsafe.Add(ref scratch, ComponentLength);
			ref ulong sum = ref Unsafe.Add(ref scratch, 2 * ComponentLength);
			AddLaneRows(ref left, ref Unsafe.Add(ref left, ComponentLength), ref leftSum, LimbCount, vectors);
			AddLaneRows(ref right, ref Unsafe.Add(ref right, ComponentLength), ref rightSum, LimbCount, vectors);

			for (int v = 0; v < vectors; ++v)
			{
				AccumulateLanes(ref left, ref right, v, ref columns);
				AccumulateLanes(ref Unsafe.Add(ref left, ComponentLength), ref Unsafe.Add(ref right, ComponentLength), v, ref Unsafe.Add(ref columns, WideLength));
				AccumulateLanes(ref leftSum, ref rightSum, v, ref sum);
			}

			CombineKaratsuba(ref columns, ref sum, vectors);
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public static void SubtractColumns(ref ulong columns, ref ulong subtrahend)
		{
			SubtractColumnRows(ref columns, ref subtrahend);
			SubtractColumnRows(ref Unsafe.Add(ref columns, WideLength), ref Unsafe.Add(ref subtrahend, WideLength));
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public static void AddColumns(ref ulong columns, ref ulong addend)
		{
			AddColumnRows(ref columns, ref addend);
			AddColumnRows(ref Unsafe.Add(ref columns, WideLength), ref Unsafe.Add(ref addend, WideLength));
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public static void AddShifted(ref ulong columns, ref ulong value)
		{
			AddLaneRows(ref Unsafe.Add(ref columns, ComponentLength), ref value, ref Unsafe.Add(ref columns, ComponentLength), LimbCount, 1);
			AddLaneRows(ref Unsafe.Add(ref columns, WideLength + ComponentLength), ref Unsafe.Add(ref value, ComponentLength), ref Unsafe.Add(ref columns, WideLength + ComponentLength), LimbCount, 1);
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public static void Reduce(ref ulong columns, ref ulong result, int vectors)
		{
			for (int v = 0; v < vectors; ++v)
			{
				int i = v * TVector.Count;
				SM9Lanes<TVector>.Reduce2(ref Unsafe.Add(ref columns, i), ref Unsafe.Add(ref columns, WideLength + i), ref Unsafe.Add(ref result, i), ref Unsafe.Add(ref result, ComponentLength + i));
			}
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		static void ISM9FieldLanes<SM9Fp2>.Reduce2(ref ulong columns, ref ulong otherColumns, ref ulong result, ref ulong otherResult)
		{
			Reduce(ref columns, ref result, 1);
			Reduce(ref otherColumns, ref otherResult, 1);
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public static void MultiplyReduce(ref ulong left, ref ulong right, ref ulong result, ref ulong columns, ref ulong scratch, int vectors)
		{
			Multiply(ref left, ref right, ref columns, ref scratch, vectors);
			Reduce(ref columns, ref result, vectors);
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public static void Add(ref ulong left, ref ulong right, ref ulong result)
		{
			AddLaneRows(ref left, ref right, ref result, 2 * LimbCount, 1);
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public static void Triple(ref ulong value, ref ulong result)
		{
			TripleLaneRows(ref value, ref result, 2 * LimbCount);
		}

		// 15u·x = 15·(u·x) with u·x = −2x1 + x0·u: the real part 2(3p − x1), below 6p, is weakly reduced before the factor 15, as 90p would be past 2^260, and then both parts are, from below 15.0015p.
		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public static void MultiplyByThreeB(ref ulong value, ref ulong result, int vectors)
		{
			for (int v = 0; v < vectors; ++v)
			{
				int i = v * TVector.Count;
				TimesULaneRows(ref Unsafe.Add(ref value, ComponentLength + i), ref Unsafe.Add(ref result, i));
				FifteenLaneRows(ref Unsafe.Add(ref result, i), ref Unsafe.Add(ref result, i));
				FifteenLaneRows(ref Unsafe.Add(ref value, i), ref Unsafe.Add(ref result, ComponentLength + i));
			}
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public static void WeakReduce(ref ulong value, int vectors)
		{
			for (int v = 0; v < vectors; ++v)
			{
				int i = v * TVector.Count;
				WeakReduceLaneRows(ref Unsafe.Add(ref value, i));
				WeakReduceLaneRows(ref Unsafe.Add(ref value, ComponentLength + i));
			}
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public static void SubtractFromCover(ref ulong left, ref ulong right, ref ulong result)
		{
			SubtractFromCoverLaneRows(ref left, ref right, ref result, 2 * LimbCount);
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public static void SubtractTwo(ref ulong value, ref ulong first, ref ulong second, ref ulong result)
		{
			SubtractTwoLaneRows(ref value, ref first, ref second, ref result);
			SubtractTwoLaneRows(ref Unsafe.Add(ref value, ComponentLength), ref Unsafe.Add(ref first, ComponentLength), ref Unsafe.Add(ref second, ComponentLength), ref Unsafe.Add(ref result, ComponentLength));
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public static void ConditionalSelect(ref ulong mask, ref ulong whenSet, ref ulong whenClear, ref ulong result, int vectors)
		{
			SelectLaneRows(ref mask, ref whenSet, ref whenClear, ref result, 2 * LimbCount, vectors);
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public static void ConditionalNegate(ref ulong mask, ref ulong value)
		{
			NegateLaneRows(ref mask, ref value, 2 * LimbCount);
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public static void MoveDown(ref ulong value, int distance, ref ulong result)
		{
			MoveDownLaneRows(ref value, distance, ref result, 2 * LimbCount);
		}

		// 3b = 15u would take u·Z into lane 2, whose real part 2(3p − z1) times 15 is past what a product takes, so ThreeBLaneTwo takes it from the reduced Z².
		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public static void DoublingOperands(ref ulong point, ref ulong left, ref ulong right, int vectors)
		{
			SM9Lanes<TVector>.DoublingOperands(ref point, ref left, ref right, 2 * LimbCount, false, vectors);
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public static void ThreeBLaneTwo(ref ulong value, ref ulong scratch, int vectors)
		{
			MultiplyByThreeB(ref value, ref scratch, vectors);
			ConditionalSelect(ref MemoryMarshal.GetReference(LaneTwoMask), ref scratch, ref value, ref value, vectors);
		}
	}

	// The shuffles of the formulas on one point, X, Y and Z in lanes 0 to 2 of an element. The patterns: the operands of the doubling, (Y, Y, Z, X) and (Y, Z, Z, Y); of its second round, (w2, w1, w0, w0) and (w0, w0, w0, w3); its result, (q3, q0, q1); the left operand of the addition, (X, Y, Z, X, Y, Z, X, Z) and Y into lane 3; the terms of its second round, (q4, q3, q6, q1, q0, q1) and (q5, q0, q7, q2, ·, q2), and its right operand from the left one, (2, 3, 4, 5, 1, 0); and its result, (q1, q3, q5) and (q0, q2, q4). SpreadE broadcasts lane 2. Vectors of a whole row shuffle in registers; narrower ones through rows of permuted, as many as a shuffle takes.
	private const ulong DoublingLeftPattern = 0x76540211;

	private const ulong DoublingRightPattern = 0x76541221;

	private const ulong DoublingMiddleLeft = 0x76540012;

	private const ulong DoublingMiddleRight = 0x76543000;

	private const ulong DoublingResultPattern = 0x76543103;

	private const ulong AdditionLeft = 0x20210210;

	private const ulong AdditionLeftSum = 0x76541210;

	private const ulong AdditionFirstTerms = 0x76101634;

	private const ulong AdditionSecondTerms = 0x76242705;

	private const ulong AdditionRight = 0x76015432;

	private const ulong AdditionResultFirst = 0x76543531;

	private const ulong AdditionResultSecond = 0x76543420;

	// The rows of permuted that the shuffles take.
	internal const int PermutedRows = 3;

	// The lane masks and factors of those shuffles.
	private static ReadOnlySpan<ulong> LaneTwoMask => [0, 0, ulong.MaxValue, 0, 0, 0, 0, 0];

	private static ReadOnlySpan<ulong> LanesTwoAndThree => [0, 0, ulong.MaxValue, ulong.MaxValue, 0, 0, 0, 0];

	private static ReadOnlySpan<ulong> LaneThree => [0, 0, 0, ulong.MaxValue, 0, 0, 0, 0];

	private static ReadOnlySpan<ulong> LanesZeroTwoAndFive => [ulong.MaxValue, 0, ulong.MaxValue, 0, 0, ulong.MaxValue, 0, 0];

	private static ReadOnlySpan<ulong> LanesOneAndTwo => [0, ulong.MaxValue, ulong.MaxValue, 0, 0, 0, 0, 0];

	private static ReadOnlySpan<ulong> DoublingThreeB => [1, 1, 15, 1, 1, 1, 1, 1];

	private static ReadOnlySpan<ulong> DoublingMiddleScale => [8, 8, 1, 1, 1, 1, 1, 1];

	private static ReadOnlySpan<ulong> DoublingResultScale => [2, 1, 1, 1, 1, 1, 1, 1];

	private static ReadOnlySpan<ulong> AdditionLeftScale => [1, 1, 1, 1, 3, 1, 1, 1];

	// left = (Y, Y, Z, X) and right = (Y, Z, Z, Y) for count rows of a point, lane 2 of right times 15 where fifteen is set: 3b·Z for b = 5, with limbs below 2^30.9 for those of Z below 2^27.
	[MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.AggressiveOptimization)]
	private static void DoublingOperands(ref ulong point, ref ulong left, ref ulong right, int count, bool fifteen, int vectors)
	{
		for (int l = 0; l < count; ++l)
		{
			int row = RowLength * l;
			ref ulong x = ref Unsafe.Add(ref point, row);
			ref ulong y = ref Unsafe.Add(ref right, row);

			if (TVector.Count == RowLength)
			{
				TVector p = TVector.Load(in x);
				TVector.Permute(p, p, DoublingLeftPattern).Store(ref Unsafe.Add(ref left, row));
				TVector.Permute(p, p, DoublingRightPattern).Store(ref y);
			}
			else
			{
				TVector.PermuteFull(in x, in x, ref Unsafe.Add(ref left, row), DoublingLeftPattern);
				TVector.PermuteFull(in x, in x, ref y, DoublingRightPattern);
			}

			if (fifteen)
			{
				for (int i = 0; i < vectors * TVector.Count; i += TVector.Count)
				{
					TVector.Multiply(TVector.Load(in Unsafe.Add(ref y, i)), TVector.Load(in DoublingThreeB[i])).Store(ref Unsafe.Add(ref y, i));
				}
			}
		}
	}

	// From w = (Y², YZ, t2, XY), t2 = 3b·Z²: left = (t2, YZ, t0, t0) with t0 = Y² + 9p − 3t2, as 9p covers 3t2, and right = (8Y², 8Y², Y² + t2, XY). With reduced w, t0 is below 10.0001p in limbs below 2^28.3, 8Y² below 8.0008p in limbs below 2^29 and Y² + t2 below 2.0002p in limbs below 2^27.
	[MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.AggressiveOptimization)]
	internal static void DoublingMiddle(ref ulong w, ref ulong left, ref ulong right, int count, ref ulong permuted, int vectors)
	{
		ReadOnlySpan<ulong> nineP = NineP;

		for (int c = 0; c < count; c += LimbCount)
		{
			for (int m = 0; m < LimbCount; ++m)
			{
				int row = RowLength * (c + m);
				ref ulong x = ref Unsafe.Add(ref w, row);
				TVector cover = TVector.Create(nineP[m]);

				if (TVector.Count == RowLength)
				{
					TVector p = TVector.Load(in x);
					TVector t2 = TVector.Permute(p, p, SpreadE);
					(TVector.Permute(p, p, DoublingMiddleLeft) + (cover - t2 - (t2 << 1) & TVector.Load(in LanesTwoAndThree[0]))).Store(ref Unsafe.Add(ref left, row));
					(TVector.Multiply(TVector.Permute(p, p, DoublingMiddleRight), TVector.Load(in DoublingMiddleScale[0])) + (t2 & TVector.Load(in LaneTwo[0]))).Store(ref Unsafe.Add(ref right, row));
					continue;
				}

				TVector.PermuteFull(in x, in x, ref permuted, SpreadE);
				TVector.PermuteFull(in x, in x, ref Unsafe.Add(ref permuted, RowLength), DoublingMiddleLeft);
				TVector.PermuteFull(in x, in x, ref Unsafe.Add(ref permuted, 2 * RowLength), DoublingMiddleRight);

				for (int i = 0; i < vectors * TVector.Count; i += TVector.Count)
				{
					TVector t2 = TVector.Load(in Unsafe.Add(ref permuted, i));
					(TVector.Load(in Unsafe.Add(ref permuted, RowLength + i)) + (cover - t2 - (t2 << 1) & TVector.Load(in LanesTwoAndThree[i]))).Store(ref Unsafe.Add(ref left, row + i));
					(TVector.Multiply(TVector.Load(in Unsafe.Add(ref permuted, 2 * RowLength + i)), TVector.Load(in DoublingMiddleScale[i])) + (t2 & TVector.Load(in LaneTwo[i]))).Store(ref Unsafe.Add(ref right, row + i));
				}
			}
		}
	}

	// From q = (t2·8Y², YZ·8Y², t0·(Y² + t2), t0·XY): (2·q3, q0 + q2, q1), below 2.0002p in limbs below 2^27 for reduced q.
	[MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.AggressiveOptimization)]
	internal static void DoublingResult(ref ulong q, ref ulong result, int count, ref ulong permuted, int vectors)
	{
		for (int l = 0; l < count; ++l)
		{
			int row = RowLength * l;
			ref ulong x = ref Unsafe.Add(ref q, row);

			if (TVector.Count == RowLength)
			{
				TVector p = TVector.Load(in x);
				(TVector.Multiply(TVector.Permute(p, p, DoublingResultPattern), TVector.Load(in DoublingResultScale[0])) + (TVector.Permute(p, p, SpreadE) & TVector.Load(in LaneOne[0]))).Store(ref Unsafe.Add(ref result, row));
				continue;
			}

			TVector.PermuteFull(in x, in x, ref permuted, DoublingResultPattern);
			TVector.PermuteFull(in x, in x, ref Unsafe.Add(ref permuted, RowLength), SpreadE);

			for (int i = 0; i < vectors * TVector.Count; i += TVector.Count)
			{
				(TVector.Multiply(TVector.Load(in Unsafe.Add(ref permuted, i)), TVector.Load(in DoublingResultScale[i])) + (TVector.Load(in Unsafe.Add(ref permuted, RowLength + i)) & TVector.Load(in LaneOne[i]))).Store(ref Unsafe.Add(ref result, row + i));
			}
		}
	}

	// (X, Y, Z, X + Y, Y, Z, X, Z) from a point, for the right operand (X2, Y2, 3b·Z2, X2 + Y2, Z2, Y2, 3b·Z2, 3b·X2), whose products are (X1X2, Y1Y2, 3b·Z1Z2, (X1 + Y1)(X2 + Y2), Y1Z2, Z1Y2, 3b·X1Z2, 3b·Z1X2).
	[MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.AggressiveOptimization)]
	internal static void AdditionOperands(ref ulong point, ref ulong result, int count, ref ulong permuted, int vectors)
	{
		for (int l = 0; l < count; ++l)
		{
			int row = RowLength * l;
			ref ulong x = ref Unsafe.Add(ref point, row);

			if (TVector.Count == RowLength)
			{
				TVector p = TVector.Load(in x);
				(TVector.Permute(p, p, AdditionLeft) + (TVector.Permute(p, p, AdditionLeftSum) & TVector.Load(in LaneThree[0]))).Store(ref Unsafe.Add(ref result, row));
				continue;
			}

			TVector.PermuteFull(in x, in x, ref permuted, AdditionLeft);
			TVector.PermuteFull(in x, in x, ref Unsafe.Add(ref permuted, RowLength), AdditionLeftSum);

			for (int i = 0; i < vectors * TVector.Count; i += TVector.Count)
			{
				(TVector.Load(in Unsafe.Add(ref permuted, i)) + (TVector.Load(in Unsafe.Add(ref permuted, RowLength + i)) & TVector.Load(in LaneThree[i]))).Store(ref Unsafe.Add(ref result, row + i));
			}
		}
	}

	// From the products q of the first round, the operands of the second, left = (t4, t3, T3, t1 − T2, 3t0, t1 + T2) and right = (T3, t1 − T2, 3t0, t1 + T2, t3, t4), with t0 = q0, t1 = q1, T2 = q2 = 3b·Z1Z2, t3 = q3 + 9p − q0 − q1, t4 = q4 + q5 and T3 = 3b·y3 = q6 + q7, t1 − T2 taken as q1 + 3p − q2. For reduced q the terms are below 10.0001p, 4.0001p, 3.0003p and 2.0002p for t3, t1 − T2, 3t0 and the others, in limbs below 2^28.3, 2^27.6, 2^27.6 and 2^27. vectors covers lanes 0 to 5.
	[MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.AggressiveOptimization)]
	internal static void AdditionSecondOperands(ref ulong q, ref ulong left, ref ulong right, int count, ref ulong permuted, int vectors)
	{
		ReadOnlySpan<ulong> threeP = ThreeP;
		ReadOnlySpan<ulong> nineP = NineP;

		for (int c = 0; c < count; c += LimbCount)
		{
			for (int m = 0; m < LimbCount; ++m)
			{
				int row = RowLength * (c + m);
				ref ulong x = ref Unsafe.Add(ref q, row);
				ref ulong y = ref Unsafe.Add(ref left, row);
				TVector three = TVector.Create(threeP[m]);
				TVector nine = TVector.Create(nineP[m]);

				if (TVector.Count == RowLength)
				{
					TVector p = TVector.Load(in x);
					TVector b = TVector.Permute(p, p, AdditionSecondTerms);
					TVector sum = TVector.Multiply(TVector.Permute(p, p, AdditionFirstTerms), TVector.Load(in AdditionLeftScale[0])) + (b & TVector.Load(in LanesZeroTwoAndFive[0])) + (three - b & TVector.Load(in LaneThree[0])) + (nine - b - p & TVector.Load(in LaneOne[0]));
					sum.Store(ref y);
					TVector.Permute(sum, sum, AdditionRight).Store(ref Unsafe.Add(ref right, row));
					continue;
				}

				TVector.PermuteFull(in x, in x, ref permuted, AdditionFirstTerms);
				TVector.PermuteFull(in x, in x, ref Unsafe.Add(ref permuted, RowLength), AdditionSecondTerms);

				for (int i = 0; i < vectors * TVector.Count; i += TVector.Count)
				{
					TVector b = TVector.Load(in Unsafe.Add(ref permuted, RowLength + i));
					(TVector.Multiply(TVector.Load(in Unsafe.Add(ref permuted, i)), TVector.Load(in AdditionLeftScale[i])) + (b & TVector.Load(in LanesZeroTwoAndFive[i])) + (three - b & TVector.Load(in LaneThree[i])) + (nine - b - TVector.Load(in Unsafe.Add(ref x, i)) & TVector.Load(in LaneOne[i]))).Store(ref Unsafe.Add(ref y, i));
				}

				TVector.PermuteFull(in y, in y, ref Unsafe.Add(ref right, row), AdditionRight);
			}
		}
	}

	// From q = (t4·T3, t3·(t1 − T2), T3·3t0, (t1 − T2)(t1 + T2), 3t0·t3, (t1 + T2)·t4): (q1 + 3p − q0, q3 + q2, q5 + q4), below 4.0001p for reduced q.
	[MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.AggressiveOptimization)]
	internal static void AdditionResult(ref ulong q, ref ulong result, int count, ref ulong permuted, int vectors)
	{
		ReadOnlySpan<ulong> threeP = ThreeP;

		for (int c = 0; c < count; c += LimbCount)
		{
			for (int m = 0; m < LimbCount; ++m)
			{
				int row = RowLength * (c + m);
				ref ulong x = ref Unsafe.Add(ref q, row);
				TVector three = TVector.Create(threeP[m]);

				if (TVector.Count == RowLength)
				{
					TVector p = TVector.Load(in x);
					TVector b = TVector.Permute(p, p, AdditionResultSecond);
					(TVector.Permute(p, p, AdditionResultFirst) + (three - b & TVector.Load(in LaneZero[0])) + (b & TVector.Load(in LanesOneAndTwo[0]))).Store(ref Unsafe.Add(ref result, row));
					continue;
				}

				TVector.PermuteFull(in x, in x, ref permuted, AdditionResultFirst);
				TVector.PermuteFull(in x, in x, ref Unsafe.Add(ref permuted, RowLength), AdditionResultSecond);

				for (int i = 0; i < vectors * TVector.Count; i += TVector.Count)
				{
					TVector b = TVector.Load(in Unsafe.Add(ref permuted, RowLength + i));
					(TVector.Load(in Unsafe.Add(ref permuted, i)) + (three - b & TVector.Load(in LaneZero[i])) + (b & TVector.Load(in LanesOneAndTwo[i]))).Store(ref Unsafe.Add(ref result, row + i));
				}
			}
		}
	}

	// left + right in count rows of vectors vectors. Rows that take every lane lie one after another, so they go as one run of vectors.
	[MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.AggressiveOptimization)]
	private static void AddLaneRows(ref ulong left, ref ulong right, ref ulong result, int count, int vectors)
	{
		if (vectors * TVector.Count == RowLength)
		{
			for (int i = 0; i < count * RowLength; i += TVector.Count)
			{
				(TVector.Load(in Unsafe.Add(ref left, i)) + TVector.Load(in Unsafe.Add(ref right, i))).Store(ref Unsafe.Add(ref result, i));
			}

			return;
		}

		for (int l = 0; l < count; ++l)
		{
			for (int i = 0; i < vectors * TVector.Count; i += TVector.Count)
			{
				int row = RowLength * l + i;
				(TVector.Load(in Unsafe.Add(ref left, row)) + TVector.Load(in Unsafe.Add(ref right, row))).Store(ref Unsafe.Add(ref result, row));
			}
		}
	}

	[MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.AggressiveOptimization)]
	private static void TripleLaneRows(ref ulong value, ref ulong result, int count)
	{
		for (int l = 0; l < count; ++l)
		{
			int row = RowLength * l;
			TVector x = TVector.Load(in Unsafe.Add(ref value, row));
			(x + (x << 1)).Store(ref Unsafe.Add(ref result, row));
		}
	}

	// left + 3p − right in count rows, 3p covering the limbs of a reduced right.
	[MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.AggressiveOptimization)]
	private static void SubtractFromCoverLaneRows(ref ulong left, ref ulong right, ref ulong result, int count)
	{
		ReadOnlySpan<ulong> threeP = ThreeP;

		for (int c = 0; c < count; c += LimbCount)
		{
			for (int m = 0; m < LimbCount; ++m)
			{
				int row = RowLength * (c + m);
				(TVector.Load(in Unsafe.Add(ref left, row)) + TVector.Create(threeP[m]) - TVector.Load(in Unsafe.Add(ref right, row))).Store(ref Unsafe.Add(ref result, row));
			}
		}
	}

	// value + 9p − first − second for one component, then weakly reduced: 9p covers the limbs of the two reduced subtrahends, below 2^27 each, so every limb stays non-negative, and the value is below 11.25p.
	[MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.AggressiveOptimization)]
	private static void SubtractTwoLaneRows(ref ulong value, ref ulong first, ref ulong second, ref ulong result)
	{
		ReadOnlySpan<ulong> nineP = NineP;
		TVector t0 = Difference(ref value, ref first, ref second, nineP, 0);
		TVector t1 = Difference(ref value, ref first, ref second, nineP, 1);
		TVector t2 = Difference(ref value, ref first, ref second, nineP, 2);
		TVector t3 = Difference(ref value, ref first, ref second, nineP, 3);
		TVector t4 = Difference(ref value, ref first, ref second, nineP, 4);
		TVector t5 = Difference(ref value, ref first, ref second, nineP, 5);
		TVector t6 = Difference(ref value, ref first, ref second, nineP, 6);
		TVector t7 = Difference(ref value, ref first, ref second, nineP, 7);
		TVector t8 = Difference(ref value, ref first, ref second, nineP, 8);
		TVector t9 = Difference(ref value, ref first, ref second, nineP, 9);
		Carry(ref t0, ref t1, ref t2, ref t3, ref t4, ref t5, ref t6, ref t7, ref t8, ref t9);
		WeakReduce(t0, t1, t2, t3, t4, t5, t6, t7, t8, t9, ref result);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static TVector Difference(ref ulong value, ref ulong first, ref ulong second, ReadOnlySpan<ulong> nineP, int l)
	{
		int row = RowLength * l;
		return TVector.Load(in Unsafe.Add(ref value, row)) + TVector.Create(nineP[l]) - TVector.Load(in Unsafe.Add(ref first, row)) - TVector.Load(in Unsafe.Add(ref second, row));
	}

	// 15·value for one component below 1.0001p in limbs below 2^26, then weakly reduced from below 15.0015p in limbs below 2^30.
	[MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.AggressiveOptimization)]
	private static void FifteenLaneRows(ref ulong value, ref ulong result)
	{
		TVector t0 = Fifteen(ref value, 0);
		TVector t1 = Fifteen(ref value, 1);
		TVector t2 = Fifteen(ref value, 2);
		TVector t3 = Fifteen(ref value, 3);
		TVector t4 = Fifteen(ref value, 4);
		TVector t5 = Fifteen(ref value, 5);
		TVector t6 = Fifteen(ref value, 6);
		TVector t7 = Fifteen(ref value, 7);
		TVector t8 = Fifteen(ref value, 8);
		TVector t9 = Fifteen(ref value, 9);
		Carry(ref t0, ref t1, ref t2, ref t3, ref t4, ref t5, ref t6, ref t7, ref t8, ref t9);
		WeakReduce(t0, t1, t2, t3, t4, t5, t6, t7, t8, t9, ref result);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static TVector Fifteen(ref ulong value, int l)
	{
		TVector x = TVector.Load(in Unsafe.Add(ref value, RowLength * l));
		return (x << 4) - x;
	}

	// The real part of u·x, 2(3p − x1) for the ten rows of a reduced x1, below 6p in limbs below 2^28, weakly reduced.
	[MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.AggressiveOptimization)]
	private static void TimesULaneRows(ref ulong value, ref ulong result)
	{
		ReadOnlySpan<ulong> threeP = ThreeP;
		TVector t0 = Doubled(ref value, threeP, 0);
		TVector t1 = Doubled(ref value, threeP, 1);
		TVector t2 = Doubled(ref value, threeP, 2);
		TVector t3 = Doubled(ref value, threeP, 3);
		TVector t4 = Doubled(ref value, threeP, 4);
		TVector t5 = Doubled(ref value, threeP, 5);
		TVector t6 = Doubled(ref value, threeP, 6);
		TVector t7 = Doubled(ref value, threeP, 7);
		TVector t8 = Doubled(ref value, threeP, 8);
		TVector t9 = Doubled(ref value, threeP, 9);
		Carry(ref t0, ref t1, ref t2, ref t3, ref t4, ref t5, ref t6, ref t7, ref t8, ref t9);
		WeakReduce(t0, t1, t2, t3, t4, t5, t6, t7, t8, t9, ref result);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static TVector Doubled(ref ulong value, ReadOnlySpan<ulong> threeP, int l)
	{
		return TVector.Create(threeP[l]) - TVector.Load(in Unsafe.Add(ref value, RowLength * l)) << 1;
	}

	// One component of one vector in place, as WeakReduceRows.
	[MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.AggressiveOptimization)]
	private static void WeakReduceLaneRows(ref ulong rows)
	{
		Load(ref rows, out TVector t0, out TVector t1, out TVector t2, out TVector t3, out TVector t4, out TVector t5, out TVector t6, out TVector t7, out TVector t8, out TVector t9);
		Carry(ref t0, ref t1, ref t2, ref t3, ref t4, ref t5, ref t6, ref t7, ref t8, ref t9);
		WeakReduce(t0, t1, t2, t3, t4, t5, t6, t7, t8, t9, ref rows);
	}

	[MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.AggressiveOptimization)]
	private static void SelectLaneRows(ref ulong mask, ref ulong whenSet, ref ulong whenClear, ref ulong result, int count, int vectors)
	{
		for (int i = 0; i < vectors * TVector.Count; i += TVector.Count)
		{
			TVector select = TVector.Load(in Unsafe.Add(ref mask, i));

			for (int l = 0; l < count; ++l)
			{
				int row = RowLength * l + i;
				TVector.ConditionalSelect(select, TVector.Load(in Unsafe.Add(ref whenSet, row)), TVector.Load(in Unsafe.Add(ref whenClear, row))).Store(ref Unsafe.Add(ref result, row));
			}
		}
	}

	// 3p − value in count rows of vector 0, in the lanes whose mask is set, 3p covering the limbs of a reduced value.
	[MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.AggressiveOptimization)]
	private static void NegateLaneRows(ref ulong mask, ref ulong value, int count)
	{
		ReadOnlySpan<ulong> threeP = ThreeP;
		TVector select = TVector.Load(in mask);

		for (int c = 0; c < count; c += LimbCount)
		{
			for (int m = 0; m < LimbCount; ++m)
			{
				ref ulong x = ref Unsafe.Add(ref value, RowLength * (c + m));
				TVector v = TVector.Load(in x);
				TVector.ConditionalSelect(select, TVector.Create(threeP[m]) - v, v).Store(ref x);
			}
		}
	}

	[MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.AggressiveOptimization)]
	private static void MoveDownLaneRows(ref ulong value, int distance, ref ulong result, int count)
	{
		for (int l = 0; l < count; ++l)
		{
			ref ulong x = ref Unsafe.Add(ref value, RowLength * l);
			ref ulong r = ref Unsafe.Add(ref result, RowLength * l);

			switch (distance)
			{
				case 1:
					TVector.PermuteFull(in x, in x, ref r, DownOne);
					break;
				case 2:
					TVector.PermuteFull(in x, in x, ref r, DownTwo);
					break;
				default:
					TVector.PermuteFull(in x, in x, ref r, DownFour);
					break;
			}
		}
	}

	// columns − subtrahend + 64p² for the twenty columns of vector 0.
	[MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.AggressiveOptimization)]
	private static void SubtractColumnRows(ref ulong columns, ref ulong subtrahend)
	{
		ReadOnlySpan<ulong> offset = Offset;

		for (int s = 0; s < WideRows; ++s)
		{
			int row = RowLength * s;
			(TVector.Load(in Unsafe.Add(ref columns, row)) - TVector.Load(in Unsafe.Add(ref subtrahend, row)) + TVector.Create(offset[s])).Store(ref Unsafe.Add(ref columns, row));
		}
	}

	[MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.AggressiveOptimization)]
	private static void AddColumnRows(ref ulong columns, ref ulong addend)
	{
		for (int s = 0; s < WideRows; ++s)
		{
			int row = RowLength * s;
			(TVector.Load(in Unsafe.Add(ref columns, row)) + TVector.Load(in Unsafe.Add(ref addend, row))).Store(ref Unsafe.Add(ref columns, row));
		}
	}

	// c0 = P0 − 2P1 + 128p² and c1 = Ps − P0 − P1 in place of P0 and P1, from nineteen columns each, column 19 of a lane product being 0; 128p² is twice the columns of 64p².
	[MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.AggressiveOptimization)]
	private static void CombineKaratsuba(ref ulong columns, ref ulong sum, int vectors)
	{
		ref ulong x1 = ref Unsafe.Add(ref columns, WideLength);
		ReadOnlySpan<ulong> offset = Offset;

		for (int i = 0; i < vectors * TVector.Count; i += TVector.Count)
		{
			for (int s = 0; s < WideRows - 1; ++s)
			{
				int row = RowLength * s + i;
				TVector p0 = TVector.Load(in Unsafe.Add(ref columns, row));
				TVector p1 = TVector.Load(in Unsafe.Add(ref x1, row));
				TVector ps = TVector.Load(in Unsafe.Add(ref sum, row));
				TVector half = TVector.Create(offset[s]);
				(p0 - (p1 << 1) + (half + half)).Store(ref Unsafe.Add(ref columns, row));
				(ps - p0 - p1).Store(ref Unsafe.Add(ref x1, row));
			}

			TVector.Create(offset[WideRows - 1] << 1).Store(ref Unsafe.Add(ref columns, RowLength * (WideRows - 1) + i));
			TVector.Zero.Store(ref Unsafe.Add(ref x1, RowLength * (WideRows - 1) + i));
		}
	}
}
