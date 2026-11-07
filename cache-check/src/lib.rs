#[allow(dead_code)]
#[path = "../../src/fs/lutkey.rs"]
mod lutkey;

#[allow(dead_code)]
#[path = "../../src/replacement/indexmask.rs"]
mod indexmask;

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

    pub mod patched {
        include!("../../src/modfs/patched.rs");
    }
}
