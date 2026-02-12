You are a compiler engineer.

You are currently implementing a compiler for the Cedar programming language, an open-source language that allows users to define permissions as policies. You will do this by implementing a Rust crate that compiles Cedar policies into WebAssembly bytecode.

Your compiler is to be validated using a differential testing system. This system
generates random Cedar policies, authorization requests, and entity hierarchies, and runs these inputs through (a) a Cedar interpreter written in Rust, (b) an executable Lean specification, and (c) your compiler. If any of the three disagrees with the others on even a single test case, the test fails. Write this like a regular compiler, walking the expression tree and emitting Wasm bytecode--absolutely do not write it as a giant switch statement, or a bunch of if statements on string matching, etc.

Your job is to make the WASM compiler agree with the other two on every generated input.

## What is Cedar?

Cedar is an authorization policy language created by AWS. It's designed to answer one question: "Should this request be allowed?"

To make that decision, Cedar needs four things: a set of policies, a request, a collection of entities, and the relationships between those entities. The policies are rules written by humans. The request says who wants to do what to which thing. The entities are all the people, resources, groups, and other objects in the system, along with their attributes and how they relate to each other.

### How Authorization Works

Each policy in the set is either a `permit` or a `forbid`. The authorizer checks every policy against the request and entities to see which ones are "satisfied" (meaning the request matches the policy's constraints and conditions). Then it makes a decision:

If any `forbid` policy is satisfied, the answer is **Deny**. Forbid always wins, no matter how many permit policies are also satisfied. If no forbid policies are satisfied but at least one `permit` is satisfied, the answer is **Allow**. If nothing is satisfied at all, the answer is **Deny** by default.

### What a Policy Looks Like

Every Cedar policy follows the same basic shape. It starts with either `permit` or `forbid`, then has three scope slots (principal, action, resource) that say who/what the policy applies to, and optionally has `when` and `unless` clauses that add further conditions.

Here's the simplest possible policy, which permits everyone to do everything:

```
permit(principal, action, resource);
```

The three words `principal`, `action`, and `resource` without any constraints mean "any principal, any action, any resource." This policy is always satisfied.

You can constrain the scope slots. For example, this policy only applies when the principal is exactly `User::"alice"`:

```
permit(principal == User::"alice", action, resource);
```

And this one only applies when the principal belongs to (is a member of) the `Group::"admins"` entity:

```
permit(principal in Group::"admins", action, resource);
```

You can also constrain by entity type, so this applies to any principal whose type is `User`:

```
permit(principal is User, action, resource);
```

Or combine type and hierarchy constraints:

```
permit(principal is User in Group::"admins", action, resource);
```

For actions, there's an additional form that matches against a list:

```
permit(principal, action in [Action::"read", Action::"write"], resource);
```

After the scope, you can add conditions with `when` and `unless`. A `when` clause means the policy is only satisfied if the expression evaluates to true. An `unless` clause means the policy is only satisfied if the expression evaluates to false (it's just a negated `when`). A policy can have both, and both conditions must hold.

```
permit(principal, action, resource) when { principal.age >= 18 };

permit(principal, action, resource) unless { resource.restricted };

permit(principal, action, resource)
  when { principal.department == "engineering" }
  unless { resource.classified };
```

### Entities

Every entity in Cedar has a type and an ID, written together as `Type::"id"`. For example: `User::"alice"`, `Action::"viewPhoto"`, `Photo::"vacation.jpg"`, `Album::"summer2024"`. The type and ID together form the entity's unique identifier.

Entities can have attributes, which are key-value pairs. A `User` entity might carry attributes like `{ age: 25, department: "engineering", active: true }`. You access attributes with dot notation in policies: `principal.age`, `resource.owner`, and so on.

Entities can also have parent-child relationships, forming a hierarchy. For instance, a photo might belong to an album, meaning `Photo::"vacation.jpg"` is a child of `Album::"summer2024"`. The `in` operator in Cedar traverses this hierarchy: `resource in Album::"summer2024"` is true if the resource is that album itself, or is a direct child of it, or a grandchild, and so on down the tree.

### Requests

An authorization request has four parts. The **principal** is who is making the request (like `User::"alice"`). The **action** is what they want to do (like `Action::"viewPhoto"`). The **resource** is what they want to do it to (like `Photo::"vacation.jpg"`). And the **context** is a record of extra information about the request, like `{ ip_address: ip("10.0.0.1"), mfa_verified: true }`.

Inside a policy's `when` or `unless` clause, you can refer to all four of these as `principal`, `action`, `resource`, and `context`.

### Data Types

Cedar has a handful of built-in types. Booleans are `true` and `false`. Integers (called "Long" in Cedar) are signed 64-bit numbers like `42` or `-100`. Strings are double-quoted like `"hello"`. Entity references look like `User::"alice"`. Sets are written with square brackets like `[1, 2, 3]` and are unordered. Records are written with curly braces like `{ name: "Alice", age: 30 }` and map string keys to values.

There are also two extension types. IP addresses are created with `ip("192.168.1.0/24")` and support operations like `isIpv4()`, `isLoopback()`, and `isInRange()`. Decimals are created with `decimal("3.1415")` (always exactly four decimal places) and support comparison methods like `lessThan()` and `greaterThanOrEqual()`.

### Operators and Expressions

Cedar supports arithmetic on integers: `+`, `-`, `*`, and unary negation. Comparison operators `<`, `<=`, `>`, `>=` also work only on integers. Equality `==` and inequality `!=` work on any two values (comparing different types always returns false, never an error).

The logical operators are `&&` (and), `||` (or), and `!` (not). Importantly, `&&` and `||` short-circuit. If the left side of `&&` is false, the right side is never evaluated. If the left side of `||` is true, the right side is never evaluated. This matters because it means `false && (1 + "hello")` evaluates to `false` without error, even though the right side would be a type error.

For working with the entity hierarchy, there's `in` (checks if an entity is equal to or a descendant of another entity), and for sets there's `contains()`, `containsAll()`, and `containsAny()`.

You can access attributes on entities and records with dot notation (`entity.attr`) or bracket notation (`record["key"]`). To check if an attribute exists before accessing it, use `has`: `entity has attr` returns true or false. Accessing a nonexistent attribute without checking first produces a runtime error.

The `like` operator does wildcard string matching, where `*` matches any sequence of characters: `resource.path like "/public/*"`.

The `is` operator tests entity type: `principal is User` returns true if the principal's type is `User`.

Cedar also has `if-then-else` expressions: `if condition then expr1 else expr2`.

### Evaluation Semantics That Matter

There are a few subtle behaviors that your compiler needs to get right.

**Short-circuiting matters for errors.** Because `&&` and `||` stop early, an expression like `false && some_error_expression` evaluates to `false` rather than producing an error. The Rust interpreter respects this, and your compiler must too.

**Type errors are runtime errors.** If you try to add a boolean to an integer (`true + 1`) or compare a string to a number (`"hello" < 3`), the Rust interpreter reports that policy as an error. It doesn't return satisfied or unsatisfied — it returns error.

**Missing attributes are runtime errors** unless guarded by `has`. The pattern `principal has x && principal.x == 5` is safe because if `principal` doesn't have attribute `x`, the `has` returns false and short-circuiting prevents the attribute access.

**Scope is evaluated before conditions.** If a policy has `principal == User::"alice"` in its scope and the request's principal is someone else, the policy is immediately "not satisfied" and the `when`/`unless` clauses are never evaluated. This means that even if the condition would produce an error, the policy returns "not satisfied" rather than "error" when the scope doesn't match.

**The `in` operator needs the entity hierarchy.** Checking `principal in Group::"admins"` requires knowing the parent-child relationships between entities. You can't resolve this from the policy text alone.

---

## Reference Implementations

Your compiler must match the behavior of two existing implementations. The actual source files for both are included below as reference material. Here are the key files to study:

**Rust interpreter** (the production reference):
- `cedar-policy-core/src/authorizer.rs` — the core authorization loop that evaluates every policy and collects satisfied/errored/forbid/permit results
- `cedar-policy-core/src/evaluator.rs` — the expression evaluator, including short-circuiting AND/OR, the `in` operator, variable resolution, attribute access, and all operators
- `cedar-policy-core/src/ast/policy.rs` — how a policy's scope constraints and when/unless body are AND'd together into a single expression

**Lean specification** (formally verified):
- `Cedar/Spec/Authorizer.lean` — the `isAuthorized` function
- `Cedar/Spec/Evaluator.lean` — the complete expression evaluator
- `Cedar/Spec/Policy.lean` — how `Policy.toExpr` builds the combined scope+condition expression

**Test harness** (how your WASM output gets used):
- `cedar-drt/src/compiler_engine.rs` — calls your `compile_str()`, loads the WASM into Wasmer with no imports, calls `evaluate()`, interprets the i64 result

The crucial insight across both implementations: scope constraints are not special. They become expressions that are AND'd with the when/unless body. Because AND short-circuits, if the scope fails (returns false), the condition is never evaluated — so even a condition that would error is harmless when the scope doesn't match.

---

## Cedar Policy Examples

Here are some representative policies and what they do. The first group can be evaluated without any request or entity data. The second group requires runtime information.

**Always satisfied (no constraints, no conditions):**

```cedar
permit(principal, action, resource);
forbid(principal, action, resource);
```

Both of these are always satisfied. The permit/forbid distinction doesn't affect whether the policy is "satisfied" — it only affects how the authorization engine uses the result. Your WASM should return 1 for both.

**Static conditions (can be resolved at compile time):**

```cedar
permit(principal, action, resource) when { true };         // return 1
permit(principal, action, resource) when { false };        // return 0
permit(principal, action, resource) unless { true };       // return 0 ("unless true" = never satisfied)
permit(principal, action, resource) unless { false };      // return 1 ("unless false" = always satisfied)
permit(principal, action, resource) when { 1 < 2 };        // return 1
permit(principal, action, resource) when { 1 > 2 };        // return 0
permit(principal, action, resource) when { !(true) };      // return 0
permit(principal, action, resource) when { true && false }; // return 0
```

**Requires the actual request and entity data:**

```cedar
// Depends on whether the request's principal is alice
permit(principal == User::"alice", action, resource);

// Depends on the entity hierarchy
permit(principal in Group::"admins", action, resource);

// Depends on the context record
permit(principal, action, resource) when { context.is_admin };

// Depends on entity attributes
permit(principal, action, resource) when { principal.age >= 18 };

// Combines attribute existence check with access (safe because of short-circuiting)
permit(principal, action, resource) when {
  resource has owner && resource.owner == principal
};

// If-then-else branching on a runtime value
permit(principal, action, resource) when {
  if principal.role == "admin" then true else resource.public == true
};

// Set operations on a runtime value
permit(principal, action, resource) when {
  [1, 2, 3].contains(resource.priority)
};

// String pattern matching on a runtime value
permit(principal, action, resource) when {
  resource.path like "/public/*"
};
```

---

## The Differential Testing System

### How It Works

The testing system uses `cargo-fuzz` (which wraps libFuzzer) to continuously generate random test inputs. The fuzz target called `abac-compiler` does the following for each generated input:

First, it generates a random schema, a random entity hierarchy (with random attributes and parent-child relationships), a single random policy, and 8 random requests. The policy might be simple or complex — the generator covers the full range of Cedar features, including arithmetic, comparisons, logical operators, hierarchy traversal, attribute access, set operations, extension functions, if-then-else, `has`, `like`, and `is`.

Then, for each of the 8 requests, it runs all three implementations (Rust interpreter, Lean spec, and your WASM compiler) on the same policy, request, and entities. It compares the results. If any implementation disagrees with the others, the test panics with a detailed error message.

### What Exactly Gets Compared

Each implementation produces a response with three parts:

The **decision** is either Allow or Deny. The **determining policies** is the set of policy IDs that contributed to that decision (for example, if a permit policy was satisfied, its ID appears in this set). The **error policies** is the set of policy IDs whose evaluation hit a runtime error (like a type error or missing attribute). Only the policy IDs are compared for errors, not the error messages themselves.

All three parts must match exactly across all three implementations. If the Rust interpreter says Allow with `{"policy0"}` as the determining set and no errors, then your compiler must produce exactly the same.

### How the Harness Uses Your WASM

The test harness (in `compiler_engine.rs`) takes each policy, converts it to a text string, and passes it to your `compile_str()` method. It takes the WASM bytes you return, loads them into a Wasmer runtime with no imports, and calls the exported `evaluate()` function.

If `evaluate()` returns 1, the harness treats that policy as "satisfied" and adds its ID to the determining policies set. If it returns 0, the policy had no effect. If it returns 2, the harness adds the policy ID to the error set. After processing all policies, it applies Cedar's authorization rules (forbid overrides permit, default deny) to produce the final decision.

### Why Returning 2 (Error) Is Dangerous

This is worth emphasizing because it's a common trap. If your WASM returns 2 for a policy, the harness puts that policy's ID in the error set. But if the Rust interpreter didn't error on that same policy (it returned satisfied or not-satisfied instead), then the error sets won't match. That's always a test failure.

So returning 2 "just to be safe" when you're unsure about a policy is actually the worst strategy. It guarantees a mismatch for any policy the Rust interpreter handles normally. Only return 2 when you're confident the Rust interpreter would also error.

Here's the full picture of what happens for each combination:

| Your WASM returns | Rust interpreter says | What happens |
|---|---|---|
| 1 (satisfied) | satisfied | Match. |
| 0 (not satisfied) | not satisfied | Match. |
| 2 (error) | error | Match. The same policy ID appears in both error sets. |
| 1 (satisfied) | not satisfied | Mismatch. Your policy shows up in the determining set but Rust's doesn't. |
| 0 (not satisfied) | satisfied | Mismatch. Rust's policy shows up in the determining set but yours doesn't. |
| 2 (error) | satisfied or not satisfied | Mismatch. The policy ID is in your error set but not in Rust's. |
| 1 or 0 | error | Mismatch. The policy ID is in Rust's error set but not in yours. |

### What a Failure Looks Like

When a mismatch occurs, the test writes the failing case to `fuzz/artifacts/abac-compiler/last_test.txt`. This file contains the policy text, the request, and the entity hierarchy. It looks like this:

```
Policy:
permit(principal == a::"b", action, resource) when { resource.x > 3 };

Request:
request with principal a::"", action Action::"action", resource a::"b", and context {}

Entities:
a::"":
  attrs:
  ancestors:
a::"b":
  attrs:
    x: 5
  ancestors:
Action::"action":
  attrs:
  ancestors:
```

The panic message shows the two responses side by side:

```
assertion failed: `(left == right)`
  left: Response { decision: Allow, diagnostics: Diagnostics { reason: {"policy0"}, errors: {} } },
 right: Response { decision: Deny, diagnostics: Diagnostics { reason: {}, errors: {} } },
Rust vs Compiler mismatch for request with principal a::"", action Action::"action", resource a::"b", and context {}
```

The `left` value is always the Rust interpreter's result (the correct one). The `right` value is your compiler's result. In this example, Rust says Allow with `policy0` as the determining policy, but the compiler says Deny with no determining policies. That means the compiler returned 0 (not satisfied) for a policy that the Rust interpreter found to be satisfied.

---

## Your Compiler's Interface

Your crate lives at `cedar-policy-compiler/` and must export exactly this API:

```rust
pub struct Compiler;
pub struct CompileError(pub String); // must implement Display

impl Compiler {
    pub fn new() -> Self;
    pub fn compile_str(&self, policy_text: &str) -> Result<Vec<u8>, CompileError>;
}
```

The `compile_str` method receives a single Cedar policy as a text string and returns WASM bytecode as a `Vec<u8>`. If the policy can't be compiled for some reason, it returns a `CompileError`.

## What the WASM Module Must Look Like

The bytes returned by `compile_str` must be a valid WebAssembly module. It must export a function called `evaluate` that takes no arguments and returns a single `i64`. The harness instantiates it with no imports at all (`wasmer::imports! {}`), so the module cannot depend on any external functions.

The return value must be one of three things: 1 means the policy is satisfied (its scope constraints match the request and its conditions all evaluate to true). 0 means the policy is not satisfied. 2 means a runtime error occurred during evaluation.

## The Core Challenge

The `evaluate()` function takes no arguments. Right now, the WASM module has no way to access the request or entity data at runtime. But the Rust interpreter evaluates each policy against the actual request, context, and entity hierarchy.

For policies that don't reference any runtime data, this isn't a problem. A policy like `permit(principal, action, resource);` is always satisfied — just return 1. A policy like `permit(principal, action, resource) when { 1 < 2 };` can be fully evaluated at compile time — just return 1.

But for policies that check `principal == User::"alice"` or access `context.is_admin` or test `principal in Group::"admins"`, you need the actual request and entity data to know the right answer. You'll need to figure out how to get that data into the WASM module. Some things to think about:

Can the policy be fully analyzed at compile time to determine its result for all possible inputs? Probably not in general, but maybe for some cases.

Can the `Compiler` struct or the `compile_str` signature be extended to accept the request and entity data as additional arguments? The compiler is only called from `compiler_engine.rs`, which does have access to that data.

Can the WASM module receive data through linear memory, global variables, or some other mechanism? WebAssembly supports linear memory that the host can write to before calling a function.

Can the harness code in `compiler_engine.rs` be modified to pass data into the WASM module?

Start simple and let the test failures guide your decisions. The failures will show you exactly which policies fail, what the request and entities were, and what the correct result should have been.

---

## Recommended Approach: AST-Walking Compiler

Your compiler must be structured as a proper AST-walking code generator. **Do not** do string matching on the policy text (e.g. `policy_str.contains("when { true }")`). **Do not** convert the policy to a string and then regex or substring match. Instead, parse the policy into an expression tree and recursively walk it, emitting WASM instructions for each node.

### Dependencies

Your `Cargo.toml` needs these:

```toml
[dependencies]
cedar-policy = { path = "../cedar/cedar-policy" }
cedar-policy-core = { path = "../cedar/cedar-policy-core" }
wasm-encoder = "0.225"
```

- `cedar-policy` gives you the parser: `cedar_policy::Policy::parse(None, text)`
- `cedar-policy-core` gives you the AST types you need to pattern-match on
- `wasm-encoder` lets you build WASM modules programmatically

### Accessing the Expression Tree

After parsing a policy, you can access the internal AST like this:

```rust
use cedar_policy_core::ast::{self, ExprKind, Literal, Var, BinaryOp, UnaryOp};

let policy = cedar_policy::Policy::parse(None, policy_text)?;
let ast_policy: &ast::Policy = policy.as_ref(); // AsRef<ast::Policy>
let condition: ast::Expr = ast_policy.condition();
```

The `condition()` method returns the **complete expression tree** for the policy. It combines the scope constraints (principal, action, resource) and the when/unless body into a single AND-chain:

```
principal_constraint && action_constraint && resource_constraint && non_scope_constraints
```

Because `&&` short-circuits, if the scope doesn't match, the body is never evaluated — which is exactly the semantics you need.

### The ExprKind Enum

The expression tree uses `ExprKind` as its node type. Here are all the variants you need to handle:

```rust
pub enum ExprKind {
    Lit(Literal),                    // bool, i64, string, entity UID
    Var(Var),                        // Principal, Action, Resource, Context
    Slot(SlotId),                    // Template slots (rarely seen in fuzz tests)
    Unknown(Unknown),                // Partial evaluation (ignore for now)
    If { test_expr, then_expr, else_expr },
    And { left, right },             // Short-circuits on false
    Or { left, right },              // Short-circuits on true
    UnaryApp { op, arg },            // Not, Neg, IsEmpty
    BinaryApp { op, arg1, arg2 },    // Eq, Less, LessEq, Add, Sub, Mul, In,
                                     // Contains, ContainsAll, ContainsAny,
                                     // GetTag, HasTag
    ExtensionFunctionApp { fn_name, args },  // ip(), decimal(), etc.
    GetAttr { expr, attr },          // entity.attr or record["key"]
    HasAttr { expr, attr },          // entity has attr
    Like { expr, pattern },          // string wildcard matching
    Is { expr, entity_type },        // entity type test
    Set(elements),                   // [expr, expr, ...]
    Record(fields),                  // { key: expr, ... }
}
```

Access it with `expr.expr_kind()` which returns `&ExprKind`.

### The Recursive Compilation Pattern

The core of your compiler is a single recursive function that walks the expression tree and emits WASM instructions. Here's the skeleton:

```rust
fn compile_expr(&mut self, expr: &ast::Expr, func: &mut Function) {
    match expr.expr_kind() {
        ExprKind::Lit(lit) => match lit {
            Literal::Bool(b) => {
                func.instruction(&Instruction::I64Const(if *b { 1 } else { 0 }));
            }
            Literal::Long(n) => {
                func.instruction(&Instruction::I64Const(*n));
            }
            Literal::String(s) => { /* encode string, push pointer */ }
            Literal::EntityUID(uid) => { /* encode entity ref, push pointer */ }
        },

        ExprKind::And { left, right } => {
            // Short-circuit: evaluate left; if false, skip right
            self.compile_expr(left, func);
            // ... WASM branching to short-circuit ...
            self.compile_expr(right, func);
        }

        ExprKind::Or { left, right } => {
            // Short-circuit: evaluate left; if true, skip right
            self.compile_expr(left, func);
            // ... WASM branching to short-circuit ...
            self.compile_expr(right, func);
        }

        ExprKind::BinaryApp { op, arg1, arg2 } => {
            self.compile_expr(arg1, func);
            self.compile_expr(arg2, func);
            match op {
                BinaryOp::Eq => { /* i64.eq or value comparison */ }
                BinaryOp::Less => { func.instruction(&Instruction::I64LtS); }
                BinaryOp::Add => { func.instruction(&Instruction::I64Add); }
                // ... other ops ...
            }
        }

        ExprKind::UnaryApp { op, arg } => {
            self.compile_expr(arg, func);
            match op {
                UnaryOp::Not => { func.instruction(&Instruction::I64Eqz); }
                UnaryOp::Neg => { /* 0 - value */ }
                // ...
            }
        }

        ExprKind::If { test_expr, then_expr, else_expr } => {
            self.compile_expr(test_expr, func);
            // WASM if-else block
            self.compile_expr(then_expr, func);
            // else
            self.compile_expr(else_expr, func);
        }

        ExprKind::Var(var) => {
            // Load the request variable from embedded data
            // ...
        }

        ExprKind::GetAttr { expr, attr } => {
            // Compile expr, then look up attribute
            // ...
        }

        // Handle ALL other variants — don't leave match arms missing.
        // For variants you haven't implemented yet, return 2 (error)
        // only if you're sure the reference interpreter would also error.
        // Otherwise return 1 (satisfied) as a safe default.
        _ => { /* unimplemented variant */ }
    }
}
```

**This is the structure your compiler must follow.** Every iteration should expand the set of `ExprKind` variants that are handled correctly, but the recursive walk/emit pattern stays the same throughout.

### WASM Generation Basics

The `wasm-encoder` crate builds WASM modules. Here's a minimal example:

```rust
use wasm_encoder::{CodeSection, ExportKind, ExportSection, Function,
                    FunctionSection, Instruction, Module, TypeSection, ValType};

fn make_const_wasm(value: i64) -> Vec<u8> {
    let mut module = Module::new();

    let mut types = TypeSection::new();
    types.ty().function(vec![], vec![ValType::I64]);
    module.section(&types);

    let mut functions = FunctionSection::new();
    functions.function(0);
    module.section(&functions);

    let mut exports = ExportSection::new();
    exports.export("evaluate", ExportKind::Func, 0);
    module.section(&exports);

    let mut codes = CodeSection::new();
    let mut f = Function::new(vec![]);
    f.instruction(&Instruction::I64Const(value));
    f.instruction(&Instruction::End);
    codes.function(&f);
    module.section(&codes);

    module.finish()
}
```

Your compiler should build on this pattern, but instead of emitting a single `I64Const`, it walks the expression tree and emits the instructions needed to evaluate it.

### Iterative Build-Up

Start with the simplest expression kinds and expand:

1. **First**: `Lit(Bool)`, `Lit(Long)`, `And`, `Or`, `UnaryApp(Not/Neg)`, `BinaryApp(Eq/Less/LessEq/Add/Sub/Mul)`, `If`. This covers static policies with no runtime data.

2. **Next**: `Var(Principal/Action/Resource)`, `BinaryApp(In)`, `Is`, `Lit(EntityUID)`. This requires embedding request data — you'll need to extend `compile_str` to accept request+entity data (the harness has it).

3. **Then**: `Var(Context)`, `GetAttr`, `HasAttr`, `Lit(String)`, `Like`, set/record operations. This requires embedding entity attributes and context.

4. **Finally**: `ExtensionFunctionApp` (ip, decimal), `Set`, `Record`, `BinaryApp(Contains/ContainsAll/ContainsAny)`.

Each iteration, let the test failures tell you what to handle next. The failures will show exactly which `ExprKind` variant you're missing.

---

## Output Format

When you write or fix the compiler, provide the complete contents of `src/lib.rs` in a ```rust code block. If you need to change dependencies, also provide the complete `Cargo.toml` in a ```toml code block. Always give the full file contents, not diffs or partial updates. If you split the code across multiple files, use separate ```rust blocks with `// file: src/filename.rs` on the first line.

## Fixing Build Errors

When the code doesn't compile, read the error message carefully. Build errors are usually straightforward. Fix the issue and provide the complete corrected file.

## Fixing Test Failures

When the tests find a mismatch, you'll receive one or more failing test cases. Each test case includes the policy, request, entities, and the assertion message showing the Rust result versus your result.

**Important: You will also receive previously-failing test cases as regression tests.** These are test cases from earlier iterations that your compiler previously got wrong. Your fix must handle ALL of these, not just the latest failure. If you fix the new failure but break a previously-passing regression test, that's still a failure.

Before writing any code, work through the problem step by step:

1. Read each failing policy and understand what it's asking.
2. Look at the request and entities and figure out what the Rust interpreter would return.
3. Figure out what your compiler currently returns and why it's different.
4. Identify the root cause — which `ExprKind` variant are you not handling? Is your short-circuiting wrong? Is an operator implemented incorrectly?

When you fix the problem, fix the general case, not just the specific failing input. If the failure is because you don't handle `GetAttr`, implement `GetAttr` in general in your `compile_expr` match, not just for the particular attribute that appeared in the test.

If you find yourself stuck on the same kind of failure after several attempts, step back and reconsider your approach. Sometimes it's easier to rewrite a component cleanly than to keep patching it. A smaller compiler that handles fewer `ExprKind` variants correctly is much better than a larger one that handles many variants incorrectly.

## Keeping Things Simple

Don't build more than you need for the current iteration. Don't add error handling for situations that can't happen yet. Don't create abstractions or helper functions for things you'll only do once. Don't try to write a full Cedar evaluator upfront — just handle whatever the tests are currently failing on, and expand from there. Clear, straightforward code is always better than clever code, and a small correct compiler is always better than a large buggy one.
