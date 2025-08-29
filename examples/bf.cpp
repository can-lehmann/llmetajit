#include <cinttypes>
#include <cstdlib>

extern "C" {
  void output(char);
  char input();
  void debug();
}

class Bf {
private:
  char* code = nullptr;
  size_t code_size = 0;

  size_t loop_stack_size = 0;
  size_t loop_stack_capacity = 512;
  size_t* loop_stack = nullptr;

  size_t tape_size = 512;
  uint8_t* tape = nullptr;

  size_t pc = 0;
  size_t pos = 0;
public:
  Bf() {
    code = ".+++[>+++<-].>.";
    while (code[code_size] != '\0') {
      code_size++;
    }
    tape = new uint8_t[tape_size]();
    loop_stack = new size_t[loop_stack_capacity]();
  }

  static uint8_t* constness() {
    uint8_t* bf = new uint8_t[sizeof(Bf)]();

    size_t code_size = 100;
    uint8_t* code = new uint8_t[code_size]();
    for (size_t it = 0; it < code_size; it++) {
      code[it] = ~uint8_t(0);
    }

    *(size_t*)&bf[__builtin_offsetof(Bf, pc)] = ~size_t(0);
    *(size_t*)&bf[__builtin_offsetof(Bf, code_size)] = ~size_t(0);
    *(uint8_t**)&bf[__builtin_offsetof(Bf, code)] = code;

    return bf;
  }

  void step() {
    if (pc >= code_size) {
      return;
    }
    char inst = code[pc];
    switch (inst) {
      case '<':
        if (pos == 0) {
          pos = tape_size - 1;
        } else {
          pos--;
        }
      break;
      case '>':
        if (pos == tape_size - 1) {
          pos = 0;
        } else {
          pos++;
        }
      break;
      case '+': tape[pos]++; break;
      case '-': tape[pos]--; break;
      case '[':
        if (tape[pos]) {
          loop_stack[loop_stack_size++] = pc;
        } else {
          size_t level = 1;
          while (level > 0) {
            pos++;
            switch (code[pc]) {
              case '[': level++; break;
              case ']': level--; break;
            }
          }
        }
      break;
      case ']':
        if (tape[pos]) {
          pc = loop_stack[loop_stack_size - 1];
        } else {
          loop_stack_size--;
        }
      break;
      case '.': output(tape[pos]); break;
      case ',': tape[pos] = input(); break;
    }
    pc++;
  }
};

extern "C" {
  void* init() {
    return (void*) new Bf();
  }

  void* init_constness() {
    return (void*) Bf::constness();
  }

  __attribute__((flatten))
  void step(void* state) {
    Bf* bf = (Bf*) state;
    bf->step();
  }
}
