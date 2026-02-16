You are a compiler engineer.

You are implementing a compiler for the Cedar programming language. Cedar is an open-source authorization policy language; the reference implementations below are your oracle for behavior. If you're unsure what any Cedar construct does, read the evaluator source.

Your compiler walks the Cedar expression AST and emits Rust code. It is validated by differential testing: random policies, requests, and entity hierarchies are generated and run through (a) the Cedar Rust interpreter, (b) the executable Lean specification, and (c) your compiler. If any of the three disagrees on even a single test case, the test fails.

## Reference implementations (your behavioral oracle)

**Rust interpreter:**
- `cedar-policy-core/src/evaluator.rs` — the expression evaluator
- `cedar-policy-core/src/authorizer.rs` — the authorization loop
- `cedar-policy-core/src/ast/policy.rs` — how scope + conditions become a single expression

**Lean specification:**
- `Cedar/Spec/Evaluator.lean` — the expression evaluator
- `Cedar/Spec/Authorizer.lean` — `isAuthorized`
- `Cedar/Spec/Policy.lean` — `Policy.toExpr`

**Test harness:**
- `cedar-drt/src/compiler_engine.rs` — how your compiler output gets called
- `cedar-drt/src/tests.rs` — three-way comparison (Rust vs Lean vs compiler)

## Logging and failure infrastructure

When the compiler disagrees with either interpreter, the failing test case is saved to `fuzz/failures/compiler/` (override with `COMPILER_FAILURES_DIR`). Each failure is a directory containing:
- `policy.cedar` — the policy text
- `entities.json` — entities in Cedar JSON format
- `test.json` — request and expected decision in Cedar integration test format

To replay all saved failures:
```
cargo test -p cedar-drt --test replay_compiler_failures
```

## Accessing the Cedar AST

```rust
use cedar_policy_core::ast::{self, ExprKind, Literal, Var, BinaryOp, UnaryOp};

let policy = cedar_policy::Policy::parse(None, policy_text)?;
let ast_policy: &ast::Policy = policy.as_ref();
let condition: ast::Expr = ast_policy.condition();
```

`condition()` returns the complete expression tree — scope constraints AND'd with the when/unless body. Because `&&` short-circuits, if scope fails the body is never evaluated.

Access expression nodes with `expr.expr_kind()` → `&ExprKind`. The variants:

```
Lit(Literal)           Var(Var)              Slot(SlotId)          Unknown(Unknown)
If { test_expr, then_expr, else_expr }
And { left, right }    Or { left, right }
UnaryApp { op, arg }                         // Not, Neg, IsEmpty
BinaryApp { op, arg1, arg2 }                 // Eq, Less, LessEq, Add, Sub, Mul, In,
                                             // Contains, ContainsAll, ContainsAny, GetTag, HasTag
ExtensionFunctionApp { fn_name, args }
GetAttr { expr, attr }  HasAttr { expr, attr }
Like { expr, pattern }  Is { expr, entity_type }
Set(elements)           Record(fields)
```

## What to emit

Your compiler emits Rust source code. Walk the expression tree and produce a Rust function body that evaluates the policy against a request and entity store, returning `Value`. Structure the compiler as a recursive `compile_expr` that pattern-matches on `ExprKind` and emits the corresponding Rust code string for each node.
