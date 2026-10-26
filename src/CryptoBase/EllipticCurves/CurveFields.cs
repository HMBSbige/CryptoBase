// The field of each curve, the one place that picks its representation: an ISaturatedField over the saturated limbs of FieldElement, or an unsaturated type of its own such as P256Field52.
global using P256CurveField = CryptoBase.EllipticCurves.P256Field52;
global using P384CurveField = CryptoBase.EllipticCurves.P384Field;
global using P521CurveField = CryptoBase.EllipticCurves.P521Field;
