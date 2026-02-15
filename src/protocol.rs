use std::io::{self, Read, Write};

/// Read a length-prefixed message: 4-byte LE length + UTF-8 body
pub fn read_message(reader: &mut impl Read) -> io::Result<String> {
    let mut len_buf = [0u8; 4];
    reader.read_exact(&mut len_buf)?;
    let len = u32::from_le_bytes(len_buf) as usize;
    if len > 64 * 1024 * 1024 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "message too large"));
    }
    let mut buf = vec![0u8; len];
    reader.read_exact(&mut buf)?;
    String::from_utf8(buf).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

/// Write a length-prefixed message: 4-byte LE length + UTF-8 body
pub fn write_message(writer: &mut impl Write, msg: &str) -> io::Result<()> {
    let bytes = msg.as_bytes();
    writer.write_all(&(bytes.len() as u32).to_le_bytes())?;
    writer.write_all(bytes)?;
    writer.flush()
}

/// Read raw bytes (for file transfers)
pub fn read_raw_bytes(reader: &mut impl Read, size: usize) -> io::Result<Vec<u8>> {
    let mut buf = vec![0u8; size];
    reader.read_exact(&mut buf)?;
    Ok(buf)
}

/// Write raw bytes (for file transfers)
pub fn write_raw_bytes(writer: &mut impl Write, data: &[u8]) -> io::Result<()> {
    writer.write_all(data)?;
    writer.flush()
}
