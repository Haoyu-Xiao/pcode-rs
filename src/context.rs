use std::{fmt::Display, ops::BitOr, os::raw::c_void};

use anyhow::Result;
use serde::{Deserialize, Serialize};

use crate::bindings::*;

#[derive(Debug)]
pub struct Context {
    pub internal: *mut c_void,
}

impl Drop for Context {
    fn drop(&mut self) {
        unsafe { destroy_context(self.internal) }
    }
}

impl Context {
    pub fn new(_internal: PContext) -> Self {
        Context {
            internal: _internal,
        }
    }

    pub fn translate(
        &mut self,
        bytes: &[u8],
        // num_bytes: usize,
        address: u64,
        max_insns: usize,
        flags: TranslationFlags,
    ) -> Result<Vec<PcodeOp>> {
        use std::ffi::{c_char, c_uint, c_ulonglong, CStr};

        // if bytes.len() < num_bytes {
        //     return Err(anyhow::anyhow!("num_bytes exceeds the length of bytes"));
        // }
        let num_bytes = bytes.len();
        let ptr = bytes.as_ptr() as *const c_char;
        let mut translation = unsafe {
            translate(
                self.internal,
                ptr,
                num_bytes as c_uint,
                address as c_ulonglong,
                max_insns as c_uint,
                flags.as_u32() as c_uint,
            )
        };
        if translation.is_null() {
            let err = unsafe {
                CStr::from_ptr(error_str.as_ptr())
                    .to_string_lossy()
                    .into_owned()
            };
            return anyhow::bail!(err);
        }

        let internal = self.internal;

        let mut pcode_ops = Vec::new();
        let count = unsafe { get_translation_op_count(translation) };

        for i in 0..count {
            let pcode_op = unsafe { get_translation_op(translation, i) };
            pcode_ops.push(pcode_op.into());
        }

        Ok(pcode_ops)
    }

    pub fn disassemble(
        &mut self,
        bytes: &[u8],
        num_bytes: usize,
        address: u64,
        max_instructions: u64,
    ) -> Result<Vec<Instruction>> {
        use std::ffi::{c_char, c_uint, c_ulonglong, CStr};
        let ptr = bytes.as_ptr() as *const c_char;
        let mut disassembly = unsafe {
            disassemble(
                self.internal,
                ptr,
                num_bytes as c_uint,
                address as c_ulonglong,
                max_instructions as c_uint,
            )
        };
        if disassembly.is_null() {
            let err = unsafe {
                CStr::from_ptr(error_str.as_ptr())
                    .to_string_lossy()
                    .into_owned()
            };
            return Err(anyhow::anyhow!(err));
        }

        let mut instructions = Vec::new();
        let count = unsafe { get_disassembly_insn_count(disassembly) };
        for i in 0..count {
            let instruction = unsafe { get_disassembly_insn(disassembly, i) };
            instructions.push(instruction.into());
        }

        Ok(instructions)
    }
}

#[derive(Debug, Clone)]
pub struct PcodeOp {
    pub opcode: OpCode,
    pub output: Option<VarnodeData>,
    pub inputs: Vec<VarnodeData>,
}

impl From<PPcodeOp> for PcodeOp {
    fn from(pcode_op: PPcodeOp) -> Self {
        let opcode = OpCode::from(unsafe { get_translation_op_opcode(pcode_op) });
        let mut var = PVarnodeData::default();
        let output: Option<VarnodeData> =
            if unsafe { get_translation_op_output(pcode_op, &mut var) } {
                Some(var.into())
            } else {
                None
            };
        let count = unsafe { get_translation_op_input_count(pcode_op) };
        let inputs: Vec<VarnodeData> = (0..count)
            .map(|x| {
                if !unsafe { get_translation_op_input(pcode_op, x, &mut var) } {
                    panic!("Failed to get input varnode");
                }
                var.into()
            })
            .collect::<Vec<_>>();

        PcodeOp {
            opcode,
            output,
            inputs,
        }
    }
}

impl Display for PcodeOp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(output) = &self.output {
            write!(f, "{} = ", output)?;
        }
        write!(f, "{}", self.opcode)?;
        for input in &self.inputs {
            write!(f, " {}", input)?;
        }
        Ok(())
    }
}

/// A disassembly instruction
#[derive(Debug)]
pub struct Instruction {
    address: Address,
    length: usize,
    mnem: String,
    body: String,
}

impl From<PDisassemblyInstruction> for Instruction {
    fn from(instruction: PDisassemblyInstruction) -> Self {
        let mut paddress = PAddress::default();
        unsafe {
            get_insn_address(instruction, &mut paddress);
        }
        let address = paddress.into();
        let length = unsafe { get_insn_length(instruction) };
        let mnem = unsafe {
            let cstr = get_insn_mnem(instruction);
            std::ffi::CStr::from_ptr(cstr)
                .to_string_lossy()
                .into_owned()
        };
        let body = unsafe {
            let cstr = get_insn_body(instruction);
            std::ffi::CStr::from_ptr(cstr)
                .to_string_lossy()
                .into_owned()
        };
        Instruction {
            address,
            length,
            mnem,
            body,
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub enum AddrSpace {
    Ram,
    Register,
    Unique,
    Stack,
    Constant,
    Other(String),
}

impl From<PAddrSpace> for AddrSpace {
    fn from(addr_space: PAddrSpace) -> Self {
        let name = unsafe {
            std::ffi::CStr::from_ptr(addr_space.name)
                .to_string_lossy()
                .into_owned()
        };
        match name.as_str() {
            "ram" => AddrSpace::Ram,
            "register" => AddrSpace::Register,
            "unique" => AddrSpace::Unique,
            "stack" => AddrSpace::Stack,
            "const" => AddrSpace::Constant,
            _ => AddrSpace::Other(name),
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
pub struct Address {
    pub space: AddrSpace,
    pub offset: u64,
}

impl From<PAddress> for Address {
    fn from(address: PAddress) -> Self {
        Address {
            space: address.space.into(),
            offset: address.offset,
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
pub struct VarnodeData {
    pub space: AddrSpace,
    pub offset: u64,
    pub size: u32,
    pub reg_name: Option<String>,
}

impl From<PVarnodeData> for VarnodeData {
    fn from(varnode_data: PVarnodeData) -> Self {
        use std::ffi::CStr;
        VarnodeData {
            space: varnode_data.space.into(),
            offset: varnode_data.offset,
            size: varnode_data.size as u32,
            reg_name: if varnode_data.reg_name.is_null() {
                None
            } else {
                Some(unsafe {
                    CStr::from_ptr(varnode_data.reg_name)
                        .to_string_lossy()
                        .into_owned()
                })
            },
        }
    }
}

impl Display for VarnodeData {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.space {
            AddrSpace::Ram => write!(f, "(ram,0x{:X},{})", self.offset, self.size),
            AddrSpace::Register => {
                if let Some(name) = &self.reg_name {
                    write!(f, "{}", name)
                } else {
                    write!(f, "(reg,0x{:X},{})", self.offset, self.size)
                }
            }
            AddrSpace::Unique => write!(f, "(unique,{},{})", self.offset, self.size),
            AddrSpace::Stack => write!(f, "(stack,0x{:X},{})", self.offset, self.size),
            AddrSpace::Constant => write!(f, "(const,{},{})", self.offset, self.size),
            AddrSpace::Other(name) => write!(
                f,
                "(other({}),{},{})",
                name.to_lowercase(),
                self.offset,
                self.size
            ),
        }
    }
}

/// The opcodes used in the Pcode language
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[repr(u32)]
pub enum OpCode {
    /// Auxiliary opcodes to mark the beginning of a disassembly instruction
    IMark = 0,
    /// Copy one operand to another
    Copy = 1,
    /// Load from a pointer into a specified address space
    Load = 2,
    /// Store at a pointer into a specified address space
    Store = 3,
    /// Always branch
    Branch = 4,
    /// Conditional branch
    CBranch = 5,
    /// Indirect branch (jumptable)
    BranchInd = 6,
    /// Call to an absolute address
    Call = 7,
    /// Call through an indirect address
    CallInd = 8,
    /// User-defined operation
    CallOther = 9,
    /// Return from subroutine
    Return = 10,
    // Integer/bit operations
    /// Integer comparison, equality (==)
    IntEqual = 11,
    /// Integer comparison, in-equality (!=)
    IntNotEqual = 12,
    /// Integer comparison, signed less-than (<)
    IntSLess = 13,
    /// Integer comparison, signed less-than-or-equal (<=)
    IntSLessEqual = 14,
    /// Integer comparison, unsigned less-than (<)
    IntLess = 15,
    /// Integer comparison, unsigned less-than-or-equal (<=)
    IntLessEqual = 16,
    /// Zero extension
    IntZExt = 17,
    /// Sign extension
    IntSExt = 18,
    /// Addition, signed or unsigned (+)
    IntAdd = 19,
    /// Subtraction, signed or unsigned (-)
    IntSub = 20,
    /// Test for unsigned carry
    IntCarry = 21,
    /// Test for signed carry
    IntSCarry = 22,
    /// Test for signed borrow
    IntSBorrow = 23,
    /// Twos complement
    Int2Comp = 24,
    /// Logical/bitwise negation (~)
    IntNegate = 25,
    /// Logical/bitwise exclusive-or (^)
    IntXor = 26,
    /// Logical/bitwise and (&)
    IntAnd = 27,
    /// Logical/bitwise or (|)
    IntOr = 28,
    /// Left shift (<<)
    IntLeft = 29,
    /// Right shift, logical (>>)
    IntRight = 30,
    /// Right shift, arithmetic (>>)
    IntSRight = 31,
    /// Integer multiplication, signed and unsigned (*)
    IntMult = 32,
    /// Integer division, unsigned (/)
    IntDiv = 33,
    /// Integer division, signed (/)
    IntSDiv = 34,
    /// Remainder/modulo, unsigned (%)
    IntRem = 35,
    /// Remainder/modulo, signed (%)
    IntSRem = 36,
    /// Boolean negate (!)
    BoolNegate = 37,
    /// Boolean exclusive-or (^^)
    BoolXor = 38,
    /// Boolean and (&&)
    BoolAnd = 39,
    /// Boolean or (||)
    BoolOr = 40,
    // Floating point operations
    /// Floating-point comparison, equality (==)
    FloatEqual = 41,
    /// Floating-point comparison, in-equality (!=)
    FloatNotEqual = 42,
    /// Floating-point comparison, less-than (<)
    FloatLess = 43,
    /// Floating-point comparison, less-than-or-equal (<=)
    FloatLessEqual = 44,
    // Slot 45 is currently unused
    /// Not-a-number test (NaN)
    FloatNaN = 46,
    /// Floating-point addition (+)
    FloatAdd = 47,
    /// Floating-point division (/)
    FloatDiv = 48,
    /// Floating-point multiplication (*)
    FloatMult = 49,
    /// Floating-point subtraction (-)
    FloatSub = 50,
    /// Floating-point negation (-)
    FloatNeg = 51,
    /// Floating-point absolute value (abs)
    FloatAbs = 52,
    /// Floating-point square root (sqrt)
    FloatSqrt = 53,
    /// Convert an integer to a floating-point
    FloatInt2Float = 54,
    /// Convert between different floating-point sizes
    FloatFloat2Float = 55,
    /// Round towards zero
    FloatTrunc = 56,
    /// Round towards +infinity
    FloatCeil = 57,
    /// Round towards -infinity
    FloatFloor = 58,
    /// Round towards nearest
    FloatRound = 59,
    // Internal opcodes for simplification. Not
    // typically generated in a direct translation.

    // Data-flow operations
    /// Phi-node operator
    MultiEqual = 60,
    /// Copy with an indirect effect
    Indirect = 61,
    /// Concatenate
    Piece = 62,
    /// Truncate
    SubPiece = 63,
    /// Cast from one data-type to another
    Cast = 64,
    /// Index into an array ([])
    PtrAdd = 65,
    /// Drill down to a sub-field  (->)
    PtrSub = 66,
    /// Look-up a \e segmented address
    SegmentOp = 67,
    /// Recover a value from the \e constant \e pool
    CPoolRef = 68,
    /// Allocate a new object (new)
    New = 69,
    /// Insert a bit-range
    Insert = 70,
    /// Extract a bit-range
    Extract = 71,
    /// Count the 1-bits
    PopCount = 72,
    /// Count the leading 0-bits
    LzCount = 73,
    /// Value indicating the end of the op-code values
    Max = 74,
}

impl From<u32> for OpCode {
    fn from(value: u32) -> Self {
        match value {
            0 => OpCode::IMark,
            1 => OpCode::Copy,
            2 => OpCode::Load,
            3 => OpCode::Store,
            4 => OpCode::Branch,
            5 => OpCode::CBranch,
            6 => OpCode::BranchInd,
            7 => OpCode::Call,
            8 => OpCode::CallInd,
            9 => OpCode::CallOther,
            10 => OpCode::Return,
            11 => OpCode::IntEqual,
            12 => OpCode::IntNotEqual,
            13 => OpCode::IntSLess,
            14 => OpCode::IntSLessEqual,
            15 => OpCode::IntLess,
            16 => OpCode::IntLessEqual,
            17 => OpCode::IntZExt,
            18 => OpCode::IntSExt,
            19 => OpCode::IntAdd,
            20 => OpCode::IntSub,
            21 => OpCode::IntCarry,
            22 => OpCode::IntSCarry,
            23 => OpCode::IntSBorrow,
            24 => OpCode::Int2Comp,
            25 => OpCode::IntNegate,
            26 => OpCode::IntXor,
            27 => OpCode::IntAnd,
            28 => OpCode::IntOr,
            29 => OpCode::IntLeft,
            30 => OpCode::IntRight,
            31 => OpCode::IntSRight,
            32 => OpCode::IntMult,
            33 => OpCode::IntDiv,
            34 => OpCode::IntSDiv,
            35 => OpCode::IntRem,
            36 => OpCode::IntSRem,
            37 => OpCode::BoolNegate,
            38 => OpCode::BoolXor,
            39 => OpCode::BoolAnd,
            40 => OpCode::BoolOr,
            41 => OpCode::FloatEqual,
            42 => OpCode::FloatNotEqual,
            43 => OpCode::FloatLess,
            44 => OpCode::FloatLessEqual,
            46 => OpCode::FloatNaN,
            47 => OpCode::FloatAdd,
            48 => OpCode::FloatDiv,
            49 => OpCode::FloatMult,
            50 => OpCode::FloatSub,
            51 => OpCode::FloatNeg,
            52 => OpCode::FloatAbs,
            53 => OpCode::FloatSqrt,
            54 => OpCode::FloatInt2Float,
            55 => OpCode::FloatFloat2Float,
            56 => OpCode::FloatTrunc,
            57 => OpCode::FloatCeil,
            58 => OpCode::FloatFloor,
            59 => OpCode::FloatRound,
            60 => OpCode::MultiEqual,
            61 => OpCode::Indirect,
            62 => OpCode::Piece,
            63 => OpCode::SubPiece,
            64 => OpCode::Cast,
            65 => OpCode::PtrAdd,
            66 => OpCode::PtrSub,
            67 => OpCode::SegmentOp,
            68 => OpCode::CPoolRef,
            69 => OpCode::New,
            70 => OpCode::Insert,
            71 => OpCode::Extract,
            72 => OpCode::PopCount,
            73 => OpCode::LzCount,
            74 => OpCode::Max,
            _ => panic!("Invalid OpCode value: {}", value),
        }
    }
}

impl From<OpCode> for u32 {
    fn from(opcode: OpCode) -> Self {
        opcode as u32
    }
}

impl Display for OpCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, PartialOrd, Ord)]
pub enum TranslationFlags {
    Default = 0,
    TerminateBlockEnding = 1,
}

impl Default for TranslationFlags {
    fn default() -> Self {
        TranslationFlags::Default
    }
}

impl TryFrom<u32> for TranslationFlags {
    type Error = String;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(TranslationFlags::Default),
            1 => Ok(TranslationFlags::TerminateBlockEnding),
            _ => Err(format!("Invalid TranslationFlags value: {}", value)),
        }
    }
}

impl BitOr for TranslationFlags {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self::Output {
        TranslationFlags::try_from(self.as_u32() | rhs.as_u32())
            .expect("Invalid TranslationFlags value")
    }
}

impl TranslationFlags {
    pub fn as_u32(&self) -> u32 {
        match self {
            TranslationFlags::Default => 0x0,
            TranslationFlags::TerminateBlockEnding => 0x1,
        }
    }
}

impl Default for PVarnodeData {
    fn default() -> Self {
        PVarnodeData {
            space: PAddrSpace::default(),
            offset: 0,
            size: 0,
            reg_name: std::ptr::null(),
        }
    }
}

impl Default for PAddress {
    fn default() -> Self {
        PAddress {
            space: PAddrSpace::default(),
            offset: 0,
        }
    }
}

impl Default for PAddrSpace {
    fn default() -> Self {
        PAddrSpace {
            name: 0 as *mut i8,
            type_: 0,
        }
    }
}

#[cfg(test)]
mod test {
    use crate::language::LanguageDefinitions;

    use super::*;

    #[test]
    fn test_translate() {
        let ldefs = LanguageDefinitions::load().unwrap();
        let mut context = ldefs.get_context("x86:LE:32:default").unwrap();
        let bytes = vec![0x90, 0x90, 0x90, 0x90];
        let result = context.translate(&bytes, 0, 10, TranslationFlags::TerminateBlockEnding);
        assert!(
            result.is_ok(),
            "Failed to translate: {:?}",
            result.unwrap_err()
        );

        let translation = result.unwrap();
        assert!(!translation.is_empty(), "Translation is null");
    }
}
