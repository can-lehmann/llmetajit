#ifndef llvm_func
#define llvm_func(name, res, ...)
#endif

llvm_func(GetParam, value_ptr, value_ptr, u)
llvm_func(ConstInt, value_ptr, type_ptr, ull, b)

llvm_func(VoidTypeInContext, type_ptr, context_ptr)
llvm_func(PointerTypeInContext, type_ptr, context_ptr, u)
llvm_func(IntTypeInContext, type_ptr, context_ptr, u)
llvm_func(StructTypeInContext, type_ptr, context_ptr, type_ptr_ptr, u, b)
llvm_func(FunctionType, type_ptr, type_ptr, type_ptr_ptr, u, b)

llvm_func(BuildAlloca, value_ptr, builder_ptr, type_ptr, ptr)
llvm_func(BuildStore, value_ptr, builder_ptr, value_ptr, value_ptr)
llvm_func(BuildLoad2, value_ptr, builder_ptr, type_ptr, value_ptr, ptr)
llvm_func(BuildGEP2, value_ptr, builder_ptr, type_ptr, value_ptr, value_ptr_ptr, u, ptr)
llvm_func(BuildBinOp, value_ptr, builder_ptr, opcode, value_ptr, value_ptr, ptr)
llvm_func(BuildCast, value_ptr, builder_ptr, opcode, value_ptr, type_ptr, ptr)
llvm_func(BuildICmp, value_ptr, builder_ptr, u, value_ptr, type_ptr, ptr)
llvm_func(BuildRetVoid, value_ptr, builder_ptr)
llvm_func(BuildCall2, value_ptr, builder_ptr, type_ptr, value_ptr, value_ptr_ptr, u, ptr)

llvm_func(GetNamedFunction, value_ptr, module_ptr, ptr)

llvm_func(BuildGuard, value_ptr, builder_ptr, value_ptr, b)

#undef llvm_func
