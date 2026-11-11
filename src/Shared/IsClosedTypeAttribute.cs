#if !NET11_0_OR_GREATER
namespace System.Runtime.CompilerServices;

// The attribute that the compiler puts on a closed class, which .NET 11 defines.
[AttributeUsage(AttributeTargets.Class, Inherited = false)]
internal sealed class IsClosedTypeAttribute : Attribute;
#endif
