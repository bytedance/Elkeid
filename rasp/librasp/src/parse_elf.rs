use std::fs::File;
use goblin::elf::{Elf, Sym};
use byteorder::{ByteOrder, LittleEndian, BigEndian};

use anyhow::{anyhow, Result};
use std::io::{Read, Seek, SeekFrom};
use log::*;
use memmap::Mmap;
const MAGIC: &[u8] = b"\xff Go buildinf:";
const RUNTIME_VERSION_MAGIC: &str = "runtime.buildVersion";
const EXPECTED_MAGIC_LEN: usize = 14;
const FLAGS_OFFSET: usize = 15;

const BUILDINFO_ALIGN: usize = 16;
const BUILDINFO_HEADER_SIZE: usize = 32;
const MAX_VAR_INT_LEN64: usize = 10;

const FLAGS_VERSION_MASK: u8  = 0x2;
const FLAGS_ENDIAN_BIG: u8   = 0x1;


fn uvarint(buf: &[u8]) -> (u64, i32) {
    let mut x: u64 = 0;
    let mut s: u32 = 0;
    for (i, &b) in buf.iter().enumerate() {
        if i == MAX_VAR_INT_LEN64 {
            return (0, -(i as i32 + 1)); // overflow
        }
        if b < 0x80 {
            if i == MAX_VAR_INT_LEN64 - 1 && b > 1 {
                return (0, -(i as i32 + 1)); // overflow
            }
            return (x | (b as u64) << s, (i + 1) as i32);
        }
        x |= ((b & 0x7F) as u64) << s;
        s += 7;
    }
    return (0, 0);
}

fn read_ptr(b: &[u8], ptr_size: usize, is_little_endian: bool) -> Option<u64> {
    match ptr_size {
        4 => {
            if is_little_endian{
                return Some(u64::from(LittleEndian::read_u32(b)));
            } else {
                return Some(u64::from(BigEndian::read_u32(b)));
            }
        }
        8 => {
            if is_little_endian{
                return Some(u64::from(LittleEndian::read_u64(b)));
            } else {
                return Some(u64::from(BigEndian::read_u64(b)));
            }
        }
        _ => None,
    }
}

fn read_data_at_address(mut file: &File, elf: &Elf, address: u64, size: usize) -> Option<Vec<u8>> {
    let section = match elf.section_headers.iter().find(|section| {
        section.sh_addr <= address && address < section.sh_addr + section.sh_size
    }) {
        Some(section) => section,
        None => return None,
    };
    
    let offset = (address - section.sh_addr) as u64;
    if let Err(_) = file.seek(SeekFrom::Start(section.sh_offset + offset)) {
        return None;
    }
    
    let mut buffer = vec![0u8; size];
    if let Err(_) = file.read_exact(&mut buffer) {
        return None;
    }
    
    Some(buffer)
}

fn find_symbol<'a>(elf: &'a Elf<'a>, symbol_name: &str) -> Option<Sym> {
    for sym in &elf.syms {
        if let Some(name) = elf.strtab.get_at(sym.st_name) {
            if name == symbol_name {
                return Some(sym.clone());
            }
        }
    }
    None
}

pub fn find_by_symbol(elf: &Elf, file: &File) -> Result<String> {
    // find runtime.buildVersion symbol
    let symbol= find_symbol(&elf, RUNTIME_VERSION_MAGIC);
    if let Some(sym) = symbol {
        // read version data
        let version_address_ptr = sym.st_value;
        let version_len = sym.st_size;
        let is_little_endian = elf.little_endian;

        let version_u8 = match read_data_at_address(&file, &elf, version_address_ptr, version_len as usize) {
            Some(data) => data,
            None => {
                let msg = format!("Failed to read version data");
                warn!("{}", msg);
                return Err(anyhow!(msg));
            }
        };
        info!("find symbol version: {:?}", version_u8);
        let ptr_size = version_len / 2;
        let version_address = match read_ptr(&version_u8, ptr_size as usize, is_little_endian) {
            Some(ptr) => ptr,
            None => {
                let msg = format!("Failed to read version addr pointer");
                warn!("{}", msg);
                return Err(anyhow!(msg));
            }
        };
        let version_address_len = match read_ptr(&version_u8[ptr_size as usize..], ptr_size as usize, is_little_endian) {
            Some(ptr) => ptr,
            None => {
                let msg = format!("Failed to read version length pointer");
                warn!("{}", msg);
                return Err(anyhow!(msg));
            }
        };

        let version_addr_u8 = match read_data_at_address(&file, &elf, version_address, version_address_len as usize) {
            Some(data) => data,
            None => {
                let msg = format!("Failed to read version data");
                warn!("{}", msg);
                return Err(anyhow!(msg));
            }
        };
        let version = String::from_utf8_lossy(&version_addr_u8).to_string();
        Ok(version)
    } else {
        let msg = format!("file {:?} Failed to find symbol: runtime.buildVersion", file);
        // warn!("{}", msg);
        Err(anyhow!(msg))
    }
}

pub fn find_by_section(elf: &Elf, file: &File, mmap: &Mmap) -> Result<String> {
    let mut version: String = String::new();
    
    // find .go.buildinfo 
    if let Some(go_buildinfo_section) = elf.section_headers.iter().find(|section| {
        if let Some(sect_name) = elf.shdr_strtab.get_at(section.sh_name) {
            sect_name == ".go.buildinfo"
        } else {
            false
        }
    }) {
        // read ".go.buildinfo" section data
        let start = go_buildinfo_section.sh_offset as usize;
        let end = (go_buildinfo_section.sh_offset + go_buildinfo_section.sh_size) as usize;
  
        // Memory map the specific section
        if mmap.len() < end {
            return Err(anyhow!("mmap length invaild")); // Return empty string if the section is out of bounds
        }
  
        // Extract the data of the section
        let buildinfo_data = &mmap[start..end];

        // check Magic
        let magic_header = &buildinfo_data[0..EXPECTED_MAGIC_LEN];
        if magic_header == MAGIC {
            let flag = buildinfo_data[FLAGS_OFFSET];
            // Since 1.18, the flags version bit is flagsVersionInl. In this case,
            // the header is followed by the string contents inline as
            // length-prefixed (as varint) string contents. First is the version
            // string, followed immediately by the modinfo string.
            if flag & FLAGS_VERSION_MASK == FLAGS_VERSION_MASK {
                let version_u8 = match read_data_at_address(&file, &elf, go_buildinfo_section.sh_addr + BUILDINFO_HEADER_SIZE as u64, MAX_VAR_INT_LEN64) {
                    Some(data) => data,
                    None => {
                        let msg = format!("Failed to read version data");
                        warn!("{}", msg);
                        return Err(anyhow!(msg));
                    }
                };
                let len = uvarint(&version_u8).0;
                let offset = uvarint(&version_u8).1;

                version = String::from_utf8_lossy(&buildinfo_data[BUILDINFO_HEADER_SIZE + offset as usize ..BUILDINFO_HEADER_SIZE + len as usize + offset as usize ]).to_string();

            } else {
                // go version < 1.18
                let ptr_size = buildinfo_data[EXPECTED_MAGIC_LEN] as usize;
                let big_endian = flag & FLAGS_VERSION_MASK == FLAGS_ENDIAN_BIG;
                // Read the version address and length based on endianness
                if let Some(version_address) = read_ptr(&buildinfo_data[BUILDINFO_ALIGN as usize..(BUILDINFO_ALIGN + ptr_size) as usize], ptr_size, !big_endian) {
                    if let Some(version_address_ptr) = read_data_at_address(&file, &elf, version_address, ptr_size * 2) {
                        let version_address_ptr_u64 = match read_ptr(&version_address_ptr[0..ptr_size], ptr_size, !big_endian) {
                            Some(ptr) => ptr,
                            None => {
                                let msg = format!("Failed to read version address pointer, {}", ptr_size);
                                warn!("{}", msg);
                                return Err(anyhow!(msg));
                            }
                        };
                        let version_len_ptr_u64 = match read_ptr(&version_address_ptr[ptr_size..ptr_size * 2], ptr_size, !big_endian) {
                            Some(ptr) => ptr,
                            None => {
                                let msg = format!("Failed to read version length pointer");
                                warn!("{}", msg);
                                return Err(anyhow!(msg));
                            }
                        };
                        let version_u8 = match read_data_at_address(&file, &elf, version_address_ptr_u64, version_len_ptr_u64 as usize) {
                            Some(data) => data,
                            None => {
                                let msg = format!("Failed to read version version data");
                                warn!("{}", msg);
                                return Err(anyhow!(msg));
                            }
                        };
                
                        version = String::from_utf8_lossy(&version_u8).to_string();
                    }
                }
            }
            return Ok(version);
        } else {
            let msg = format!("file {:?} Failed to find magic header: {:?}", file, magic_header);
            // warn!("{}", msg);
            return Err(anyhow!(msg));
        }
     } else {
        let msg = format!("file {:?} Failed to find section:.go.buildinfo", file);
        // warn!("{}", msg);
        Err(anyhow!(msg))
     }
}