use std::fs::{self, File};
use std::io::{self, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use zip::ZipArchive;

const MAX_FILENAME_LENGTH: usize = 256;
const MAX_BYTES_TO_READ: usize = 2 * 1024;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() == 1 {
        println!("Usage: {} [FILE]...", args[0]);
        println!("For any issue, contact Rahul<basicfunc@gmail.com>");
        return;
    }

    let files = match glob(&args[1]) {
        Ok(f) => f,
        Err(e) => {
            println!("{}", e);
            return;
        }
    };

    for file in files {
        let file_name = match file.to_str() {
            Some(f) => f,
            None => continue,
        };

        if file_name.len() > MAX_FILENAME_LENGTH {
            println!("File name too long.");
            continue;
        }

        print!("{}: ", file_name);

        match fs::symlink_metadata(&file) {
            Ok(meta) => {
                if meta.file_type().is_symlink() {
                    match fs::read_link(file) {
                        Ok(link) => println!("symbolic link to {}", link.display()),
                        Err(e) => println!("error reading symbolic link: {}", e),
                    }
                } else if meta.is_dir() {
                    println!("directory");
                } else {
                    regular_file(&file);
                }
            }
            Err(e) => println!("{}: {}", file_name, e),
        }
    }
}

// Little Endian
fn peek_le(c: &[u8], size: usize) -> i32 {
    let mut ret: i64 = 0;

    for i in 0..size {
        ret |= (c[i] as i64) << (i * 8);
    }

    ret as i32
}

// Big Endian
fn peek_be(c: &[u8], size: usize) -> i32 {
    let mut ret: i64 = 0;

    for i in 0..size {
        ret = (ret << 8) | (c[i] as i64 & 0xff);
    }

    ret as i32
}

fn read_elf(content_byte: &[u8]) {
    let bits = content_byte[4] as usize;
    let endian = content_byte[5];

    let elfint: fn(&[u8], usize) -> i32 = if endian == 2 { peek_be } else { peek_le };

    let exei = elfint(&content_byte[16..], 2);

    match exei {
        1 => print!("relocatable"),
        2 => print!("executable"),
        3 => print!("shared object"),
        4 => print!("core dump"),
        _ => print!("bad type"),
    }

    print!(", ");

    match bits {
        1 => print!("32-bit "),
        2 => print!("64-bit "),
        _ => (),
    }

    match endian {
        1 => print!("LSB "),
        2 => print!("MSB "),
        _ => print!("bad endian "),
    }

    let arch_type: std::collections::HashMap<&str, usize> = [
        ("alpha", 0x9026),
        ("arc", 93),
        ("arcv2", 195),
        ("arm", 40),
        ("arm64", 183),
        ("avr32", 0x18ad),
        ("bpf", 247),
        ("blackfin", 106),
        ("c6x", 140),
        ("cell", 23),
        ("cris", 76),
        ("frv", 0x5441),
        ("h8300", 46),
        ("hexagon", 164),
        ("ia64", 50),
        ("m32r88", 88),
        ("m32r", 0x9041),
        ("m68k", 4),
        ("metag", 174),
        ("microblaze", 189),
        ("microblaze-old", 0xbaab),
        ("mips", 8),
        ("mips-old", 10),
        ("mn10300", 89),
        ("mn10300-old", 0xbeef),
        ("nios2", 113),
        ("openrisc", 92),
        ("openrisc-old", 0x8472),
        ("parisc", 15),
        ("ppc", 20),
        ("ppc64", 21),
        ("s390", 22),
        ("s390-old", 0xa390),
        ("score", 135),
        ("sh", 42),
        ("sparc", 2),
        ("sparc8+", 18),
        ("sparc9", 43),
        ("tile", 188),
        ("tilegx", 191),
        ("386", 3),
        ("486", 6),
        ("x86-64", 62),
        ("xtensa", 94),
        ("xtensa-old", 0xabc7),
    ]
    .iter()
    .map(|(key, val)| (*key, *val))
    .collect();

    let archj = elfint(&content_byte[18..], 2);
    for (key, val) in &arch_type {
        if *val == archj as usize {
            print!("{}", key);
            break;
        }
    }

    let bits = bits - 1;

    let phentsize = elfint(&content_byte[42 + 12 * bits..], 2);
    let phnum = elfint(&content_byte[44 + 12 * bits..], 2);
    let phoff = elfint(&content_byte[28 + 4 * bits..], 4 + 4 * bits);

    let mut dynamic = false;

    for i in 0..phnum {
        let idx = (phoff + i * phentsize) as usize;
        let phdr = &content_byte[idx..];
        let p_type = elfint(phdr, 4);

        dynamic = (p_type == 2) || dynamic;

        if p_type != 3 && p_type != 4 {
            continue;
        }

        if p_type == 3 {
            print!(", dynamically linked")
        }
    }

    if !dynamic {
        print!(", statically linked")
    }
}

fn read_zip(f: &mut File) -> String {
    let mut buffer = [0u8; 60];

    f.read_exact(&mut buffer).unwrap();

    let content = String::from_utf8_lossy(&buffer);

    drop(buffer);

    if content.contains("word/") && content.contains("xml") {
        return String::from("Microsoft Word 2007+");
    } else if content.contains("ppt/theme") {
        return String::from("Microsoft PowerPoint 2007+");
    } else if content.contains("xl/") && content.contains("xml") {
        return String::from("Microsoft Excel 2007+");
    } else {
        f.seek(SeekFrom::Start(0)).unwrap();
        let mut archive = ZipArchive::new(f).unwrap();
        for i in 0..archive.len() {
            let mut file = archive.by_index(i).unwrap();
            let filename = file.name();

            if filename == "word/document.xml" {
                return String::from("Microsoft Word 2007+");
            } else if filename == "xl/workbook.xml" {
                return String::from("Microsoft Excel 2007+");
            } else if filename == "ppt/presentation.xml" {
                return String::from("Microsoft PowerPoint 2007+");
            } else if filename == "mimetype" {
                let mut buf = [0; 20];
                file.read_exact(&mut buf).unwrap();

                if String::from_utf8_lossy(&buf).contains("epub") {
                    return String::from("EPUB document");
                }
            }
        }
    }
    String::from("Zip Archive Data")
}

fn regular_file(filename: &Path) {
    /*---------------Read file------------------------*/
    let mut file = std::fs::File::open(filename).unwrap();
    let mut content_byte = vec![0u8; MAX_BYTES_TO_READ];
    let num_byte = file.read(&mut content_byte).unwrap();
    content_byte = content_byte[..num_byte].to_vec();

    let lenb = content_byte.len();
    /*---------------Read file end------------------------*/
    let mut magic = -1;
    if lenb > 112 {
        magic = peek_le(&content_byte[60..], 4);
    }

    if lenb > 16 && content_byte.starts_with(b"\x23\x21") {
        println!("Script or data to be passed to the program following the shebang (#!)")
    } else if lenb >= 16 && content_byte.starts_with(b"{") && content_byte.ends_with(b"}") {
        println!("JSON file")
    } else if lenb > 64 && content_byte.starts_with(b"\x00\x01\x00\x00\x00") {
        println!("ttf: TrueType font")
    } else if lenb > 64 && content_byte.starts_with(b"\x4F\x54\x54\x4F") {
        println!("otf: OpenType font")
    }else if lenb > 32 && content_byte.starts_with(b"\x4d\x69\x63\x72\x6f\x73\x6f\x66\x74\x20\x43\x2f\x43\x2b\x2b\x20\x4d\x53\x46\x20\x37\x2e\x30\x30") {
        println!("PDB file");
    }else if lenb > 48 && content_byte.starts_with(b"\xED\xAB\xEE\xDB") {
        println!("RedHat Package Manager (RPM) package")
    }else if lenb > 48 && content_byte.starts_with(b"\x2E\x73\x6E\x64"){
        println!("Au audio file format")
    }
    else if lenb > 64 && content_byte.starts_with(b"\x00\x01\x00\x00\x4D\x53\x49\x53\x41\x4D\x20\x44\x61\x74\x61\x62\x61\x73\x65") {
        println!("Microsoft Money file")
    }else if lenb > 64 && content_byte.starts_with(b"\x00\x01\x00\x00\x53\x74\x61\x6E\x64\x61\x72\x64\x20\x41\x43\x45\x20\x44\x42") {
        println!("accdb: Microsoft Access 2007 Database")
    }else if lenb > 64 && content_byte.starts_with(b"\x00\x01\x00\x00\x53\x74\x61\x6E\x64\x61\x72\x64\x20\x4A\x65\x74\x20\x44\x42") {
        println!("accdb: Microsoft Access Database")
    }else if lenb > 64 && content_byte.starts_with(b"\x0A\x16\x6F\x72\x67\x2E\x62\x69\x74\x63\x6F\x69\x6E\x2E\x70\x72") {
        println!("MultiBit Bitcoin wallet file")
    }else if lenb > 32 && content_byte.starts_with(b"\x0D\x44\x4F\x43") {
        println!("DOC: DeskMate Document file")
    }else if lenb > 128 && content_byte.starts_with(b"\x23\x20\x4D\x69\x63\x72\x6F\x73\x6F\x66\x74\x20\x44\x65\x76\x65\x6C\x6F\x70\x65\x72\x20\x53\x74\x75\x64\x69\x6F"){
        println!("Microsoft Developer Studio project file")
    }else if lenb > 16 && content_byte.starts_with(b"\x23\x40\x7E\x5E"){
        println!("VBScript Encoded script")
    } else if lenb > 8 && content_byte.starts_with(b"\xAC\xED"){
        println!("Serialized Java Data")
    } else if lenb > 64 && content_byte.starts_with(b"\x42\x4C\x45\x4E\x44\x45\x52"){
        println!("Blender File Format")
    } else if lenb > 8 && content_byte.starts_with(b"\x00\x61\x73\x6D"){
        println!("WebAssembly binary format")
    }else if lenb >= 8 && content_byte.starts_with(b"\x21\x3C\x61\x72\x63\x68\x3E\x0A"){
        println!("linux deb file")
    }

    else if lenb >= 45 && content_byte.starts_with(b"\x7FELF") {
        print!("Elf file ");
        read_elf(&content_byte);
    } else if lenb >= 8 && content_byte.starts_with(b"!<arch>n") {
        println!("ar archive");
    } else if lenb > 28 && content_byte.starts_with(b"\x89PNG\x0d\x0a\x1a\x0a") {
        println!("PNG image data");
    } else if lenb > 16
        && (content_byte.starts_with(b"GIF87a") || content_byte.starts_with(b"GIF89a"))
    {
        println!("GIF image data");
    } else if lenb > 32 && content_byte.starts_with(b"\xff\xd8") {
        println!("JPEG / jpg image data");
    } else if lenb > 8 && content_byte.starts_with(b"\xca\xfe\xba\xbe") {
        println!("Java class file");
    } else if lenb > 8 && content_byte.starts_with(b"dex\n") {
        println!("Android dex file");
    } else if lenb > 500 && content_byte[257..262] == *b"ustar" {
        println!("Posix tar archive");
    } else if lenb > 5 && content_byte.starts_with(b"PK\x03\x04") {
        println!("{}", read_zip(&mut file));
    } else if lenb > 4 && content_byte.starts_with(b"BZh") {
        println!("bzip2 compressed data");
    } else if lenb > 10 && content_byte.starts_with(b"\x1f\x8b") {
        println!("gzip compressed data");
    } else if lenb > 32 && content_byte[1..4] == *b"\xfa\xed\xfe" {
        println!("Mach-O");
    } else if lenb > 36 && content_byte.starts_with(b"OggS\x00\x02") {
        println!("Ogg data");
    } else if lenb > 32 && content_byte.starts_with(b"RIF") && content_byte[8..16] == *b"WAVEfmt " {
        println!("WAV audio");
    } else if lenb > 12 && content_byte.starts_with(b"\x00\x01\x00\x00") {
        println!("TrueType font");
    } else if lenb > 12 && content_byte.starts_with(b"ttcf\x00") {
        println!("TrueType font collection");
    } else if lenb > 4 && content_byte.starts_with(b"BC\xc0\xde") {
        println!("LLVM IR bitcode")
    } else if content_byte.starts_with(b"-----BEGIN CERTIFICATE-----") {
        println!("PEM certificate")
    } else if magic != -1
        && content_byte.starts_with(b"MZ")
        && magic < (lenb - 4).try_into().unwrap()
        && &content_byte[magic as usize..magic as usize + 4] == b"\x50\x45\x00\x00"
    {
        print!("MS executable");

        if peek_le(&content_byte[magic as usize + 22..], 2) & 0x2000 != 0 {
            print!("(DLL)")
        }

        print!(" ");

        if peek_le(&content_byte[magic as usize + 20..], 2) > 70 {
            let types = [
                "",
                "native",
                "GUI",
                "console",
                "OS/2",
                "driver",
                "CE",
                "EFI",
                "EFI boot",
                "EFI runtime",
                "EFI ROM",
                "XBOX",
                "boot",
            ];

            let tp = peek_le(&content_byte[magic as usize + 92..], 2);

            if tp > 0 && (tp as usize) < types.len() {
                println!("{}", types[tp as usize]);
            }
        }
    } else if lenb > 50
        && content_byte.starts_with(b"BM")
        && &content_byte[6..10] == b"\x00\x00\x00\x00"
    {
        println!("BMP image")
    } else if lenb > 50 && content_byte.starts_with(b"\x25\x50\x44\x46") {
        println!("PDF file")
    } else if lenb > 16
        && (content_byte.starts_with(b"\x49\x49\x2a\x00")
            || content_byte.starts_with(b"\x4D\x4D\x00\x2a"))
    {
        println!("TIFF Image data")
    } else if lenb > 16
        && (content_byte.starts_with(b"\x00\x00\x00\x20\x66\x74\x79\x70")
            || content_byte.starts_with(b"\x00\x00\x00\x18\x66\x74\x79\x70")
            || content_byte.starts_with(b"\x00\x00\x00\x14\x66\x74\x79\x70"))
    {
        println!("MP4 video file")
    } else if lenb > 16
        && (content_byte.starts_with(b"ID3")
            || content_byte.starts_with(b"\xff\xfb")
            || content_byte.starts_with(b"\xff\xf3")
            || content_byte.starts_with(b"\xff\xf2"))
    {
        println!("MP3 audio file")
    } else if lenb > 16 && content_byte.starts_with(b"\x52\x61\x72\x21\x1A\x07\x01\x00") {
        println!("RAR Archive data")
    } else if lenb > 16 && content_byte.starts_with(b"\x37\x7A\xBC\xAF\x27\x1C") {
        println!("7z Archive data")
    } else if lenb > 16 && content_byte.starts_with(b"\x00\x00\x01\x00") {
        println!("MS Windows icon resource")
    } else if lenb > 16
        && content_byte
            .starts_with(b"\x53\x51\x4C\x69\x74\x65\x20\x66\x6F\x72\x6D\x61\x74\x20\x33\x00")
    {
        println!("SQLite database")
    } else if lenb > 16 && content_byte.starts_with(b"\x0A\x0D\x0D\x0A") {
        println!("PCAP-ng capture file")
    } else if lenb > 16
        && (content_byte.starts_with(b"\xD4\xC3\xB2\xA1")
            || content_byte.starts_with(b"\xA1\xB2\xC3\xD4")
            || content_byte.starts_with(b"\x4D\x3C\xB2\xA1")
            || content_byte.starts_with(b"\x4D\x3C\xB2\xA1"))
    {
        println!("PCAP capture file")
    } else if lenb > 16 && content_byte.starts_with(b"\x66\x4C\x61\x43") {
        println!("FLAC audio format")
    } else if lenb > 16 && content_byte.starts_with(b"\x54\x44\x46\x24") {
        println!("Telegram Desktop file")
    } else if lenb > 16 && content_byte.starts_with(b"\x54\x44\x45\x46") {
        println!("Telegram Desktop encrypted file")
    // println!("{:?}", files);
    } else if lenb > 16 && content_byte.starts_with(b"\x4D\x53\x43\x46") {
        println!("Microsoft Cabinet file")
    } else if lenb > 16 && content_byte.starts_with(b"\x38\x42\x50\x53") {
        println!("Photoshop document")
    } else if lenb > 32 && content_byte.starts_with(b"RIF") && &content_byte[8..11] == b"AVI" {
        println!("AVI file")
    } else if lenb > 32 && content_byte.starts_with(b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1") {
        println!("Microsoft Office (Legacy format)")
    } else if lenb > 32 && content_byte.starts_with(b"RIF") && &content_byte[8..12] == b"WEBP" {
        println!("Google Webp file")
    } else if lenb > 32 && content_byte.starts_with(b"\x7B\x5C\x72\x74\x66\x31") {
        println!("Rich Text Format")
    } else if lenb > 32
        && (content_byte.starts_with(b"<!DOCTYPE html>") || content_byte.starts_with(b"<head>"))
    {
        println!("HTML document")
    } else if lenb > 32 && content_byte.starts_with(b"<?xml version") {
        println!("XML document")
    } else {
        println!("ASCII text")
    }
}

fn glob(pattern: &str) -> io::Result<Vec<PathBuf>> {
    let mut paths = vec![];
    for entry in glob::glob(pattern).unwrap() {
        match entry {
            Ok(path) => paths.push(path),
            Err(e) => return Err(io::Error::new(io::ErrorKind::Other, e)),
        }
    }
    Ok(paths)
}
