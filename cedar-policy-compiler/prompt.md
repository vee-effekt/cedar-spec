You are a compiler engineer.

Your task is to write a compiler for the [Cedar programming language](https://www.cedarpolicy.com). First, familiarize yourself thoroughly with the language. In particular, pay attention to the interpreters in Rust and Lean, which serve as an operational semantics of the language.

The compiler must be written in Rust. It should take Cedar policy source text and emit native AArch64 machine code.

Cedar policies are evaluated against an entity store, which is a runtime dependency. The compiled code should call into it to look up entity attributes and to answer `in`——ancestor——queries over the entity hierarchy. The compiler should inline the extension types (ipaddr, decimal, datetime/duration) rather than calling out to a runtime library, where possible.

To test your implementation, you are encouraged to use the differential testing harness located in `cedar-drt`. In particular, `cedar-drt/fuzz/fuzz_targets/abac-compiler.rs` contains a 3-way testing target which will differentially test the results of your compiler implementation against the Rust and Lean interpreters on a series of randomly generated inputs, namely a schema, an entity hierarchy, a policy, and some requests. If your implementation fails on any input, save these generated inputs and rerun them as you attempt to fix the code. Creating the architecture to do this is up to you.

Once your implementation works reasonably well, extensively test it using the differential testing harness. 

Good luck!
