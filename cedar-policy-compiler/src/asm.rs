/// AArch64 instruction encoder and code buffer.

// Register aliases
pub const X0: u32 = 0;
pub const X1: u32 = 1;
pub const X2: u32 = 2;
pub const X3: u32 = 3;
pub const X4: u32 = 4;
pub const X5: u32 = 5;
pub const X6: u32 = 6;
pub const X7: u32 = 7;
pub const X8: u32 = 8;
pub const X9: u32 = 9;
pub const X10: u32 = 10;
pub const X19: u32 = 19;
pub const X20: u32 = 20;
pub const X21: u32 = 21;
pub const X22: u32 = 22;
pub const X23: u32 = 23;
pub const X24: u32 = 24;
pub const X29: u32 = 29; // FP
pub const X30: u32 = 30; // LR
pub const XZR: u32 = 31; // Zero register / SP depending on context
pub const SP: u32 = 31;

// Condition codes for b.cond
pub const COND_EQ: u32 = 0x0;
pub const COND_NE: u32 = 0x1;

pub struct CodeBuffer {
    code: Vec<u8>,
}

impl CodeBuffer {
    pub fn new() -> Self {
        Self { code: Vec::with_capacity(4096) }
    }

    pub fn emit_u32(&mut self, inst: u32) {
        self.code.extend_from_slice(&inst.to_le_bytes());
    }

    pub fn current_offset(&self) -> usize {
        self.code.len()
    }

    /// Patch a branch instruction at `offset` to target `target_offset`.
    /// Works for B and B.cond instructions.
    pub fn patch_branch(&mut self, offset: usize, target_offset: usize) {
        let inst = u32::from_le_bytes([
            self.code[offset],
            self.code[offset + 1],
            self.code[offset + 2],
            self.code[offset + 3],
        ]);
        let delta = (target_offset as i64 - offset as i64) / 4;

        let patched = if (inst >> 24) & 0xFE == 0x14 {
            // Unconditional branch B: opcode[31:26]=000101, imm26[25:0]
            let imm26 = (delta as u32) & 0x03FF_FFFF;
            (inst & 0xFC00_0000) | imm26
        } else if (inst >> 24) & 0xFF == 0x54 {
            // Conditional branch B.cond: opcode[31:24]=01010100, imm19[23:5], cond[3:0]
            let imm19 = ((delta as u32) & 0x7FFFF) << 5;
            (inst & 0xFF00_001F) | imm19
        } else if (inst >> 24) & 0xFF == 0xB4 || (inst >> 24) & 0xFF == 0xB5 {
            // CBZ/CBNZ: opcode[31:24], imm19[23:5], rt[4:0]
            let imm19 = ((delta as u32) & 0x7FFFF) << 5;
            (inst & 0xFF00_001F) | imm19
        } else {
            panic!("patch_branch: unknown instruction at offset {}: 0x{:08x}", offset, inst);
        };

        self.code[offset..offset + 4].copy_from_slice(&patched.to_le_bytes());
    }

    pub fn finish(self) -> Vec<u8> {
        self.code
    }

    pub fn len(&self) -> usize {
        self.code.len()
    }

    // ---- Instruction encodings ----

    /// RET (return to LR)
    pub fn ret(&mut self) {
        // RET x30: 1101_0110_0101_1111_0000_0000_0000_0000 = 0xD65F03C0
        self.emit_u32(0xD65F_03C0);
    }

    /// NOP
    pub fn nop(&mut self) {
        self.emit_u32(0xD503_201F);
    }

    /// MOVZ Xd, #imm16, LSL #shift  (shift = 0, 16, 32, 48)
    pub fn movz(&mut self, rd: u32, imm16: u16, shift: u32) {
        debug_assert!(shift == 0 || shift == 16 || shift == 32 || shift == 48);
        let hw = shift / 16;
        // sf=1, opc=10, hw, imm16, rd
        let inst = (1 << 31) | (0b10 << 29) | (0b100101 << 23) | (hw << 21) | ((imm16 as u32) << 5) | rd;
        self.emit_u32(inst);
    }

    /// MOVK Xd, #imm16, LSL #shift  (keep other bits)
    pub fn movk(&mut self, rd: u32, imm16: u16, shift: u32) {
        debug_assert!(shift == 0 || shift == 16 || shift == 32 || shift == 48);
        let hw = shift / 16;
        // sf=1, opc=11, hw, imm16, rd
        let inst = (1 << 31) | (0b11 << 29) | (0b100101 << 23) | (hw << 21) | ((imm16 as u32) << 5) | rd;
        self.emit_u32(inst);
    }

    /// Load a full 64-bit immediate into register using movz/movk sequence.
    pub fn mov_imm64(&mut self, rd: u32, value: u64) {
        self.movz(rd, value as u16, 0);
        if value > 0xFFFF {
            self.movk(rd, (value >> 16) as u16, 16);
        }
        if value > 0xFFFF_FFFF {
            self.movk(rd, (value >> 32) as u16, 32);
        }
        if value > 0xFFFF_FFFF_FFFF {
            self.movk(rd, (value >> 48) as u16, 48);
        }
    }

    /// ADD Xd, Xn, #imm12
    pub fn add_imm(&mut self, rd: u32, rn: u32, imm12: u32) {
        debug_assert!(imm12 < 4096);
        // sf=1, op=0, S=0, 10001, sh=0, imm12, rn, rd
        let inst = (1 << 31) | (0b00 << 29) | (0b10001 << 24) | (0 << 22) | (imm12 << 10) | (rn << 5) | rd;
        self.emit_u32(inst);
    }

    /// SUB Xd, Xn, #imm12
    pub fn sub_imm(&mut self, rd: u32, rn: u32, imm12: u32) {
        debug_assert!(imm12 < 4096);
        // sf=1, op=1, S=0, 10001, sh=0, imm12, rn, rd
        let inst = (1 << 31) | (0b10 << 29) | (0b10001 << 24) | (0 << 22) | (imm12 << 10) | (rn << 5) | rd;
        self.emit_u32(inst);
    }

    /// STP Xt1, Xt2, [Xn, #offset]! (pre-index)
    pub fn stp_pre(&mut self, rt1: u32, rt2: u32, rn: u32, offset: i32) {
        debug_assert!(offset % 8 == 0);
        let imm7 = ((offset / 8) as u32) & 0x7F;
        // opc=10, 101, type=0, L=0, pre=1(11), imm7, rt2, rn, rt1
        let inst = (0b10 << 30) | (0b101 << 27) | (0b0 << 26) | (0b011 << 23) | (imm7 << 15) | (rt2 << 10) | (rn << 5) | rt1;
        self.emit_u32(inst);
    }

    /// LDP Xt1, Xt2, [Xn], #offset (post-index)
    pub fn ldp_post(&mut self, rt1: u32, rt2: u32, rn: u32, offset: i32) {
        debug_assert!(offset % 8 == 0);
        let imm7 = ((offset / 8) as u32) & 0x7F;
        // opc=10, 101, type=0, L=1, post=1(01), imm7, rt2, rn, rt1
        let inst = (0b10 << 30) | (0b101 << 27) | (0b0 << 26) | (0b001 << 23) | (1 << 22) | (imm7 << 15) | (rt2 << 10) | (rn << 5) | rt1;
        self.emit_u32(inst);
    }

    /// STR Xt, [Xn, #offset] (unsigned offset, 8-byte aligned)
    pub fn str_imm(&mut self, rt: u32, rn: u32, offset: u32) {
        debug_assert!(offset % 8 == 0);
        let imm12 = offset / 8;
        debug_assert!(imm12 < 4096);
        // size=11, 111, V=0, 01, opc=00, imm12, rn, rt
        let inst = (0b11 << 30) | (0b111 << 27) | (0b0 << 26) | (0b01 << 24) | (0b00 << 22) | (imm12 << 10) | (rn << 5) | rt;
        self.emit_u32(inst);
    }

    /// LDR Xt, [Xn, #offset] (unsigned offset, 8-byte aligned)
    pub fn ldr_imm(&mut self, rt: u32, rn: u32, offset: u32) {
        debug_assert!(offset % 8 == 0);
        let imm12 = offset / 8;
        debug_assert!(imm12 < 4096);
        // size=11, 111, V=0, 01, opc=01, imm12, rn, rt
        let inst = (0b11 << 30) | (0b111 << 27) | (0b0 << 26) | (0b01 << 24) | (0b01 << 22) | (imm12 << 10) | (rn << 5) | rt;
        self.emit_u32(inst);
    }

    /// BL offset (branch with link, PC-relative, offset in bytes, will be divided by 4)
    pub fn bl(&mut self, offset: i32) {
        let imm26 = ((offset / 4) as u32) & 0x03FF_FFFF;
        let inst = (0b100101 << 26) | imm26;
        self.emit_u32(inst);
    }

    /// BLR Xn (branch with link to register)
    pub fn blr(&mut self, rn: u32) {
        // 1101011 0001 11111 000000 rn 00000
        let inst = 0xD63F_0000 | (rn << 5);
        self.emit_u32(inst);
    }

    /// B offset (unconditional branch, PC-relative, offset in bytes)
    pub fn b(&mut self, offset: i32) {
        let imm26 = ((offset / 4) as u32) & 0x03FF_FFFF;
        let inst = (0b000101 << 26) | imm26;
        self.emit_u32(inst);
    }

    /// B.cond offset (conditional branch, offset in bytes)
    pub fn b_cond(&mut self, cond: u32, offset: i32) {
        let imm19 = (((offset / 4) as u32) & 0x7FFFF) << 5;
        // 01010100 imm19 0 cond
        let inst = (0b01010100 << 24) | imm19 | cond;
        self.emit_u32(inst);
    }

    /// CBZ Xt, offset (compare and branch if zero, offset in bytes)
    pub fn cbz(&mut self, rt: u32, offset: i32) {
        let imm19 = (((offset / 4) as u32) & 0x7FFFF) << 5;
        // sf=1, 011010 0 imm19 rt
        let inst = (1 << 31) | (0b011010 << 25) | (0 << 24) | imm19 | rt;
        self.emit_u32(inst);
    }

    /// CBNZ Xt, offset (compare and branch if not zero, offset in bytes)
    pub fn cbnz(&mut self, rt: u32, offset: i32) {
        let imm19 = (((offset / 4) as u32) & 0x7FFFF) << 5;
        // sf=1, 011010 1 imm19 rt
        let inst = (1 << 31) | (0b011010 << 25) | (1 << 24) | imm19 | rt;
        self.emit_u32(inst);
    }

    /// CMP Xn, #imm12 (alias for SUBS XZR, Xn, #imm12)
    pub fn cmp_imm(&mut self, rn: u32, imm12: u32) {
        debug_assert!(imm12 < 4096);
        // sf=1, op=1, S=1, 10001, sh=0, imm12, rn, rd=XZR
        let inst = (1 << 31) | (0b11 << 29) | (0b10001 << 24) | (0 << 22) | (imm12 << 10) | (rn << 5) | XZR;
        self.emit_u32(inst);
    }

    /// CMP Xn, Xm (alias for SUBS XZR, Xn, Xm)
    pub fn cmp_reg(&mut self, rn: u32, rm: u32) {
        // sf=1, op=1, S=1, 01011, shift=00, 0, rm, imm6=0, rn, rd=XZR
        let inst = (1 << 31) | (0b11 << 29) | (0b01011 << 24) | (0b00 << 22) | (0 << 21) | (rm << 16) | (0 << 10) | (rn << 5) | XZR;
        self.emit_u32(inst);
    }

    /// MOV Xd, Xm (alias for ORR Xd, XZR, Xm)
    pub fn mov_reg(&mut self, rd: u32, rm: u32) {
        // sf=1, opc=01, 01010, shift=00, 0, rm, imm6=0, rn=XZR, rd
        let inst = (1 << 31) | (0b01 << 29) | (0b01010 << 24) | (0b00 << 22) | (0 << 21) | (rm << 16) | (0 << 10) | (XZR << 5) | rd;
        self.emit_u32(inst);
    }

    /// ORR Xd, Xn, Xm
    pub fn orr_reg(&mut self, rd: u32, rn: u32, rm: u32) {
        let inst = (1 << 31) | (0b01 << 29) | (0b01010 << 24) | (0b00 << 22) | (0 << 21) | (rm << 16) | (0 << 10) | (rn << 5) | rd;
        self.emit_u32(inst);
    }

    /// AND Xd, Xn, Xm
    pub fn and_reg(&mut self, rd: u32, rn: u32, rm: u32) {
        let inst = (1 << 31) | (0b00 << 29) | (0b01010 << 24) | (0b00 << 22) | (0 << 21) | (rm << 16) | (0 << 10) | (rn << 5) | rd;
        self.emit_u32(inst);
    }

    /// Emit a placeholder branch (B) to be patched later. Returns the offset of the instruction.
    pub fn emit_branch_placeholder(&mut self) -> usize {
        let off = self.current_offset();
        self.b(0);
        off
    }

    /// Emit a placeholder B.cond to be patched later. Returns the offset.
    pub fn emit_bcond_placeholder(&mut self, cond: u32) -> usize {
        let off = self.current_offset();
        self.b_cond(cond, 0);
        off
    }

    /// Emit a placeholder CBZ. Returns the offset.
    pub fn emit_cbz_placeholder(&mut self, rt: u32) -> usize {
        let off = self.current_offset();
        self.cbz(rt, 0);
        off
    }

    /// Emit a placeholder CBNZ. Returns the offset.
    pub fn emit_cbnz_placeholder(&mut self, rt: u32) -> usize {
        let off = self.current_offset();
        self.cbnz(rt, 0);
        off
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ret() {
        let mut buf = CodeBuffer::new();
        buf.ret();
        let code = buf.finish();
        assert_eq!(code, vec![0xC0, 0x03, 0x5F, 0xD6]);
    }

    #[test]
    fn test_nop() {
        let mut buf = CodeBuffer::new();
        buf.nop();
        let code = buf.finish();
        assert_eq!(code, vec![0x1F, 0x20, 0x03, 0xD5]);
    }

    #[test]
    fn test_movz() {
        let mut buf = CodeBuffer::new();
        buf.movz(X0, 42, 0);
        let code = buf.finish();
        let inst = u32::from_le_bytes([code[0], code[1], code[2], code[3]]);
        // Check sf=1, opc=10, hw=00
        assert_eq!(inst >> 29, 0b110);
        assert_eq!((inst >> 5) & 0xFFFF, 42);
        assert_eq!(inst & 0x1F, 0); // rd = x0
    }

    #[test]
    fn test_mov_reg() {
        let mut buf = CodeBuffer::new();
        buf.mov_reg(X0, X1);
        let code = buf.finish();
        let inst = u32::from_le_bytes([code[0], code[1], code[2], code[3]]);
        assert_eq!(inst & 0x1F, 0); // rd = x0
        assert_eq!((inst >> 16) & 0x1F, 1); // rm = x1
        assert_eq!((inst >> 5) & 0x1F, 31); // rn = xzr
    }

    #[test]
    fn test_patch_branch() {
        let mut buf = CodeBuffer::new();
        let placeholder = buf.emit_branch_placeholder();
        buf.nop();
        buf.nop();
        let target = buf.current_offset();
        buf.patch_branch(placeholder, target);
        let code = buf.finish();
        let inst = u32::from_le_bytes([code[0], code[1], code[2], code[3]]);
        // B at offset 0 targeting offset 12: delta = 12/4 = 3
        assert_eq!(inst & 0x03FF_FFFF, 3);
    }
}
