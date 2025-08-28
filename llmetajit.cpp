// Copyright 2025 Can Joshua Lehmann
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include <map>
#include <memory>

#include "llvm/IR/Module.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Verifier.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/Support/SourceMgr.h"
#include "llvm/IRReader/IRReader.h"
#include "llvm/Transforms/Utils/ValueMapper.h"
#include "llvm/ExecutionEngine/MCJIT.h"
#include "llvm/Support/DynamicLibrary.h"

#include "llvm-c/Core.h"

using namespace llvm;

extern "C" {
  void debug() {
    outs() << "debug\n";
  }
}

namespace llmetajit {
  class TracerGenerator {
  private:
    LLVMContext& context;
    Module* module;
    Function* interpreter;
    Function* tracer;

    IRBuilder<> builder;
    ValueToValueMapTy vmap;
    std::vector<Instruction*> remap_queue;
    std::map<BasicBlock*, BasicBlock*> blocks;
    std::map<Value*, Value*> is_const;
    std::map<Value*, Value*> emitted;
    size_t string_id = 0;

    struct LLVM_API {
      #define llvm_func(name, ...) Function* name;
      #include "llvm_api.inc.hpp"

      void setup(Module* module) {
        LLVMContext& context = module->getContext();
        Type* ptr = PointerType::get(context, 0);
        Type* builder_ptr = ptr;
        Type* context_ptr = ptr;
        Type* value_ptr = ptr;
        Type* value_ptr_ptr = ptr;
        Type* type_ptr = ptr;
        Type* type_ptr_ptr = ptr;
        Type* module_ptr = ptr;
        Type* u = IntegerType::get(context, sizeof(unsigned) * 8);
        Type* opcode = IntegerType::get(context, sizeof(unsigned) * 8);
        Type* ull = IntegerType::get(context, sizeof(unsigned long long) * 8);
        Type* b = IntegerType::get(context, sizeof(int) * 8);

        #define llvm_func(name, res, ...) \
          name = cast<Function>(module->getOrInsertFunction( \
            "LLVM" #name, \
            FunctionType::get(res, {__VA_ARGS__}, false) \
          ).getCallee());
        #include "llvm_api.inc.hpp"
      }
    };

    LLVM_API llvm_api;
  public:
    TracerGenerator(Function* _interpreter, Function* _tracer):
        context(_tracer->getContext()),
        module(_tracer->getParent()),
        interpreter(_interpreter),
        tracer(_tracer),
        builder(context) {
    }

    Value* get_builder() {
      return tracer->getArg(1);
    }

    Value* get_context() {
      return tracer->getArg(2);
    }

    Value* get_function() {
      return tracer->getArg(3);
    }

    Value* get_module() {
      return tracer->getArg(4);
    }

    Constant* get_null() {
      return ConstantPointerNull::get(PointerType::get(context, 0));
    }

    Value* get_str(const std::string& str) {
      std::string name = "empty_str";
      if (str.size() > 0) {
        name = "str_" + std::to_string(string_id++);
      }
      Type* type = ArrayType::get(Type::getInt8Ty(context), str.size() + 1);
      return module->getOrInsertGlobal(name, type, [&]() -> GlobalVariable* {
        return new GlobalVariable(
          *module,
          type,
          true,
          GlobalValue::InternalLinkage,
          ConstantDataArray::getString(context, str, true),
          name
        );
      });
    }

    template <class T>
    Value* get_u(T value) {
      return ConstantInt::get(IntegerType::get(context, sizeof(T) * 8), value);
    }

    Value* get_bool(bool value) {
      return get_u((int)value);
    }

    Value* emit_type(Type* type) {
      if (IntegerType* integer_type = dyn_cast<IntegerType>(type)) {
        return builder.CreateCall(
          llvm_api.IntTypeInContext,
          {get_context(), get_u((unsigned)integer_type->getBitWidth())}
        );
      } else if (PointerType* pointer_type = dyn_cast<PointerType>(type)) {
        return builder.CreateCall(
          llvm_api.PointerTypeInContext,
          {get_context(), get_u((unsigned)pointer_type->getAddressSpace())}
        );
      } else if (type->isVoidTy()) {
        return builder.CreateCall(
          llvm_api.VoidTypeInContext,
          {get_context()}
        );
      } else if (FunctionType* function_type = dyn_cast<FunctionType>(type)) {
        std::vector<Value*> args;
        for (Type* arg : function_type->params()) {
          args.push_back(emit_type(arg));
        }
        return builder.CreateCall(
          llvm_api.FunctionType,
          {
            emit_type(function_type->getReturnType()),
            get_ptr_array(args),
            get_u((unsigned)args.size()),
            get_bool(false)
          }
        );
      } else {
        type->print(errs());
        assert(false);
      }
    }

    Value* emit_arg(Value* value) {
      if (emitted.find(value) != emitted.end()) {
        return emitted.at(value);
      } else if (Argument* arg = dyn_cast<Argument>(value)) {
        return builder.CreateCall(
          llvm_api.GetParam,
          {get_function(), get_u((unsigned)arg->getArgNo())}
        );
      } else if (ConstantInt* constant_int = dyn_cast<ConstantInt>(value)) {
        assert(constant_int->getBitWidth() <= sizeof(unsigned long long) * 8);
        return builder.CreateCall(
          llvm_api.ConstInt,
          {
            emit_type(constant_int->getType()),
            get_u((unsigned long long)constant_int->getLimitedValue()),
            get_bool(false)
          }
        );
      } else if (Function* function = dyn_cast<Function>(value)) {
        return builder.CreateCall(
          llvm_api.GetNamedFunction,
          {get_module(), get_str(function->getName().str())}
        );
      } else {
        value->print(errs());
        assert(false);
      }
    }

    Value* get_ptr_array(const std::vector<Value*>& args) {
      Value* array = builder.CreateAlloca(
        ArrayType::get(
          PointerType::get(context, 0),
          args.size()
        ),
        0,
        ""
      );
      for (size_t it = 0; it < args.size(); it++) {
        builder.CreateStore(
          args[it],
          builder.CreateGEP(
            PointerType::get(context, 0),
            array,
            {get_u((unsigned)it)}
          )
        );
      }
      return array;
    }

    Value* emit_inst(Instruction* inst) {
      if (AllocaInst* alloca = dyn_cast<AllocaInst>(inst)) {
        return builder.CreateCall(
          llvm_api.BuildAlloca,
          {get_builder(), emit_type(alloca->getAllocatedType()), get_str("")}
        );
      } else if (LoadInst* load = dyn_cast<LoadInst>(inst)) {
        return builder.CreateCall(
          llvm_api.BuildLoad2,
          {
            get_builder(),
            emit_type(load->getType()),
            emit_arg(load->getPointerOperand()),
            get_str("")
          }
        );
      } else if (StoreInst* store = dyn_cast<StoreInst>(inst)) {
        return builder.CreateCall(
          llvm_api.BuildStore,
          {get_builder(), emit_arg(store->getValueOperand()), emit_arg(store->getPointerOperand())}
        );
      } else if (GetElementPtrInst* gep = dyn_cast<GetElementPtrInst>(inst)) {
        std::vector<Value*> indices;
        for (Value* index : gep->indices()) {
          indices.push_back(emit_arg(index));
        }
        return builder.CreateCall(
          llvm_api.BuildGEP2,
          {
            get_builder(),
            emit_type(gep->getPointerOperandType()),
            emit_arg(gep->getPointerOperand()),
            get_ptr_array(indices),
            get_u((unsigned)gep->getNumIndices()),
            get_str("")
          }
        );
      } else if (CastInst* cast = dyn_cast<CastInst>(inst)) {
        return builder.CreateCall(
          llvm_api.BuildCast,
          {
            get_builder(),
            get_u((unsigned)cast->getOpcode()),
            emit_arg(cast->getOperand(0)),
            emit_type(cast->getDestTy()),
            get_str("")
          }
        );
      } else if (ICmpInst* icmp = dyn_cast<ICmpInst>(inst)) {
        return builder.CreateCall(
          llvm_api.BuildICmp,
          {
            get_builder(),
            get_u((unsigned)icmp->getCmpPredicate()),
            emit_arg(icmp->getOperand(0)),
            emit_arg(icmp->getOperand(1)),
            get_str("")
          }
        );
      } else if (BinaryOperator* binop = dyn_cast<BinaryOperator>(inst)) {
        return builder.CreateCall(
          llvm_api.BuildBinOp,
          {
            get_builder(),
            get_u((unsigned)binop->getOpcode()),
            emit_arg(binop->getOperand(0)),
            emit_arg(binop->getOperand(1)),
            get_str("")
          }
        );
      } else if (CallInst* call = dyn_cast<CallInst>(inst)) {
        std::vector<Value*> args;
        for (Value* arg : call->args()) {
          args.push_back(emit_arg(arg));
        }
        return builder.CreateCall(
          llvm_api.BuildCall2,
          {
            get_builder(),
            emit_type(call->getFunctionType()),
            emit_arg(call->getCalledOperand()),
            get_ptr_array(args),
            get_u((unsigned)args.size()),
            get_str("")
          }
        );
      } else {
        inst->print(errs());
        assert(false);
      }
    }

    void gen(BasicBlock* block) {
      builder.SetInsertPoint(blocks.at(block));
      for (Instruction& inst : *block) {
        Instruction* clone = inst.clone();
        vmap[&inst] = clone;
        remap_queue.push_back(clone);
        if (BranchInst* branch = dyn_cast<BranchInst>(&inst)) {
          if (branch->isConditional()) {
            builder.CreateCall(
              llvm_api.BuildGuard,
              {
                get_builder(),
                emit_arg(branch->getCondition())
              }
            );
          }
          builder.Insert(clone);
        } else if (ReturnInst* ret = dyn_cast<ReturnInst>(&inst)) {
          builder.Insert(clone);
        } else {
          builder.Insert(clone);
          emitted[&inst] = emit_inst(&inst);
        }
      }
    }

    void gen() {
      llvm_api.setup(tracer->getParent());

      for (BasicBlock& block : *interpreter) {
        BasicBlock* new_block = BasicBlock::Create(context, block.getName(), tracer);
        blocks[&block] = new_block;
        vmap[&block] = new_block;
      }

      for (BasicBlock& block : *interpreter) {
        gen(&block);
      }

      for (size_t it = 0; it < interpreter->arg_size(); it++) {
        vmap[interpreter->getArg(it)] = tracer->getArg(it);
      }

      for (Instruction* inst : remap_queue) {
        RemapInstruction(inst, vmap);
      }
    }
  };
}

LLVMValueRef LLVMBuildGuard(LLVMBuilderRef builder_ref, LLVMValueRef cond_ref) {
  IRBuilder<>* builder = unwrap(builder_ref);
  LLVMContext& context = builder->getContext();
  Function* function = builder->GetInsertBlock()->getParent();
  BasicBlock* success = BasicBlock::Create(context, "guard_success", function);
  BasicBlock* fail = BasicBlock::Create(context, "guard_fail", function);
  BranchInst* branch = builder->CreateCondBr(unwrap(cond_ref), success, fail);
  builder->SetInsertPoint(fail);
  builder->CreateRet(nullptr);
  builder->SetInsertPoint(success);
  return wrap(branch);
}

char input() {
  return '\0';
}

void output(uint8_t x) {
  outs() << (int)x << '\n';
}

int main(int argc, const char** argv) {
  LLVMInitializeNativeTarget();
  LLVMInitializeNativeAsmPrinter();
  LLVMInitializeNativeAsmParser();

  SMDiagnostic diagnostic;
  std::string error;

  LLVMContext context;
  std::unique_ptr<Module> module = parseIRFile(argv[1], diagnostic, context);

  Function* interpreter = module->getFunction("step");
  Function* tracer = Function::Create(
    FunctionType::get(Type::getVoidTy(context), {
      PointerType::get(context, 0), // state
      PointerType::get(context, 0), // builder
      PointerType::get(context, 0), // context
      PointerType::get(context, 0), // function
      PointerType::get(context, 0), // module
    }, false),
    GlobalValue::InternalLinkage,
    "trace",
    module.get()
  );

  llmetajit::TracerGenerator tracer_gen(interpreter, tracer);
  tracer_gen.gen();

  tracer->print(outs());

  if (verifyModule(*module, &errs())) {
    return 1;
  }

  {
    Module* module2 = module.get();
    ExecutionEngine* mcjit = EngineBuilder(std::move(module))
      .setEngineKind(EngineKind::JIT)
      .setErrorStr(&error)
      .create();

    if (!mcjit) {
      errs() << error;
      return 1;
    }

    #define map(name) { \
      Function* function = module2->getFunction(#name); \
      assert(function); \
      mcjit->addGlobalMapping(function, (void*)&name); \
    }

    //map(debug)
    map(input)
    map(output)

    // Apparently we only need LLVMBuildGuard?
    #define llvm_func(name, res, ...) map(LLVM##name)
    #include "llvm_api.inc.hpp"

    #undef map

    mcjit->finalizeObject();

    using InitFn = void* (*)();
    InitFn init = (InitFn)mcjit->getFunctionAddress("init");
    using StepFn = void (*)(void*);
    StepFn step = (StepFn)mcjit->getFunctionAddress("step");
    using TraceFn = void (*)(void*, LLVMBuilderRef, LLVMContextRef, LLVMValueRef, LLVMModuleRef);
    TraceFn trace = (TraceFn)mcjit->getFunctionAddress("trace");

    {
      void* state = init();
      //step(state);

      Function* my_trace = Function::Create(
        FunctionType::get(Type::getVoidTy(context), {
          PointerType::get(context, 0),
        }, false),
        GlobalValue::InternalLinkage,
        "my_trace",
        module2
      );

      BasicBlock* entry = BasicBlock::Create(context, "entry", my_trace);

      IRBuilder<> builder(context);
      builder.SetInsertPoint(entry);

      for (size_t it = 0; it < 30; it++) {
        trace(state, wrap(&builder), wrap(&context), wrap(my_trace), wrap(module2));
      }
      builder.CreateRet(nullptr);
      my_trace->print(outs());
    }

    mcjit->finalizeObject();

    {
      StepFn my_trace = (StepFn)mcjit->getFunctionAddress("my_trace");
      assert(my_trace);
      void* state = init();
      debug();
      my_trace(state);
    }
  }

  return 0;
}

