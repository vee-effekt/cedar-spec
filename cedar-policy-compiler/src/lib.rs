use std::fmt;

#[derive(Debug)]
pub struct CompileError(pub String);

impl fmt::Display for CompileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

pub struct Compiler;

impl Compiler {
    pub fn new() -> Self {
        Compiler
    }

    pub fn compile_str(&self, _policy_text: &str) -> Result<Vec<u8>, CompileError> {
        Err(CompileError("not yet implemented".to_string()))
    }
}
