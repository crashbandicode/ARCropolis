pub mod utils {
    pub mod paths {
        use std::path::PathBuf;

        pub fn cache() -> PathBuf {
            PathBuf::from("sd:/unused")
        }
    }
}

pub mod modfs {
    #[derive(Debug)]
    pub enum ModFsError {
        Handler(String),
        BufferTooSmall { needed: usize, available: usize },
        Io(std::io::Error),
    }

    impl From<std::io::Error> for ModFsError {
        fn from(error: std::io::Error) -> Self {
            ModFsError::Io(error)
        }
    }

    fn stream_into(mut file: std::fs::File, buffer: &mut [u8], needed: usize) -> Result<usize, ModFsError> {
        use std::io::Read;
        let read = file.read(buffer)?;
        if read < needed && read == buffer.len() {
            return Err(ModFsError::BufferTooSmall { needed, available: buffer.len() });
        }
        Ok(read)
    }

    pub mod patched {
        include!("../../src/modfs/patched.rs");
    }
}
