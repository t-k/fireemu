//! Assets are opened relative to a retained directory capability, never reopened by path.

use fireemu_core_types::codec::{percent_decode_bytes, percent_escapes_are_well_formed, PlusMode};
use md5::{Digest, Md5};
use std::io::{Read, Seek};
use std::sync::Arc;

#[derive(Debug)]
pub(super) struct Asset {
    pub file: std::fs::File,
    pub bytes: u64,
    pub etag: String,
    pub modified: Option<std::time::SystemTime>,
}

pub(super) fn decode_uri(value: &str) -> Option<String> {
    if !percent_escapes_are_well_formed(value) {
        return None;
    }
    let input = value.as_bytes();
    let mut decoded = percent_decode_bytes(value, PlusMode::Literal).into_iter();
    let mut output = Vec::with_capacity(input.len());
    let mut i = 0;
    while i < input.len() {
        let byte = decoded.next()?;
        if input[i] == b'%' {
            let escape = input.get(i..i + 3)?;
            if b";/?:@&=+$,#".contains(&byte) {
                output.extend_from_slice(escape);
            } else {
                output.push(byte);
            }
            i += 3;
        } else {
            output.push(byte);
            i += 1;
        }
    }
    String::from_utf8(output).ok()
}

pub(super) fn open(root: &cap_std::fs::Dir, path: &str, ignore: &[String]) -> Option<Asset> {
    let decoded = decode_uri(path)?;
    let relative = decoded.strip_prefix('/')?;
    if relative.is_empty()
        || relative.contains(['\0', '\\', ':'])
        || relative.split('/').any(|p| p == "..")
    {
        return None;
    }
    let ignored = |path: &std::path::Path| {
        path.to_str().is_none_or(|p| {
            ignore
                .iter()
                .any(|pattern| super::matcher::deploy_ignore(pattern, &p.replace('\\', "/")))
        })
    };
    let relative = std::path::Path::new(relative);
    if ignored(relative) {
        return None;
    }
    if !root.metadata(relative).ok()?.is_file() {
        return None;
    }
    let resolved = root.canonicalize(relative).ok()?;
    if ignored(&resolved) {
        return None;
    }
    let mut options = cap_std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use cap_std::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NONBLOCK);
    }
    let mut file = root.open_with(&resolved, &options).ok()?.into_std();
    let metadata = file.metadata().ok()?;
    if !metadata.is_file() {
        return None;
    }
    let mut digest = Md5::new();
    let mut buffer = vec![0u8; 65536];
    loop {
        let read = file.read(&mut buffer).ok()?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    file.rewind().ok()?;
    Some(Asset {
        file,
        bytes: metadata.len(),
        etag: format!("{:x}", digest.finalize()),
        modified: metadata.modified().ok(),
    })
}

pub(super) async fn find(
    root: Option<Arc<cap_std::fs::Dir>>,
    paths: Vec<String>,
    ignore: Vec<String>,
) -> Option<(String, Asset)> {
    let root = root?;
    tokio::task::spawn_blocking(move || {
        paths
            .into_iter()
            .find_map(|path| open(&root, &path, &ignore).map(|asset| (path, asset)))
    })
    .await
    .ok()
    .flatten()
}

pub(super) struct FileBody {
    file: tokio::fs::File,
    remaining: u64,
}
impl FileBody {
    pub fn new(file: std::fs::File, remaining: u64) -> Self {
        Self {
            file: tokio::fs::File::from_std(file),
            remaining,
        }
    }
}
impl hyper::body::Body for FileBody {
    type Data = bytes::Bytes;
    type Error = std::io::Error;
    fn poll_frame(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<hyper::body::Frame<Self::Data>, Self::Error>>> {
        use tokio::io::AsyncRead;
        if self.remaining == 0 {
            return std::task::Poll::Ready(None);
        }
        let size = usize::try_from(self.remaining.min(65536)).expect("bounded chunk");
        let mut data = vec![0; size];
        let mut buffer = tokio::io::ReadBuf::new(&mut data);
        match std::pin::Pin::new(&mut self.file).poll_read(cx, &mut buffer) {
            std::task::Poll::Pending => std::task::Poll::Pending,
            std::task::Poll::Ready(Err(error)) => std::task::Poll::Ready(Some(Err(error))),
            std::task::Poll::Ready(Ok(())) => {
                let read = buffer.filled().len();
                if read == 0 {
                    return std::task::Poll::Ready(Some(Err(std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        "Hosting asset changed while streaming",
                    ))));
                }
                data.truncate(read);
                self.remaining -= read as u64;
                std::task::Poll::Ready(Some(Ok(hyper::body::Frame::data(data.into()))))
            }
        }
    }
    fn size_hint(&self) -> hyper::body::SizeHint {
        hyper::body::SizeHint::with_exact(self.remaining)
    }
    fn is_end_stream(&self) -> bool {
        self.remaining == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    struct Fixture(std::path::PathBuf);
    impl Fixture {
        fn new() -> Self {
            let stamp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let path = std::env::temp_dir()
                .join(format!("hosting-capability-{}-{stamp}", std::process::id()));
            std::fs::create_dir(&path).unwrap();
            std::fs::create_dir(path.join("public")).unwrap();
            std::fs::write(path.join("public/safe.txt"), "safe fixture").unwrap();
            std::fs::write(path.join("outside.txt"), "outside marker").unwrap();
            Self(path)
        }
        fn root(&self) -> cap_std::fs::Dir {
            cap_std::fs::Dir::open_ambient_dir(self.0.join("public"), cap_std::ambient_authority())
                .unwrap()
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            std::fs::remove_dir_all(&self.0).unwrap();
        }
    }
    fn symlink(target: &str, path: &Path) {
        #[cfg(unix)]
        std::os::unix::fs::symlink(target, path).unwrap();
        #[cfg(windows)]
        std::os::windows::fs::symlink_file(target, path)
            .expect("native Windows symlink support is required for this test");
    }
    use std::path::Path;
    #[test]
    fn deploy_ignore_matches_glob_minimatch_options() {
        let fixture = Fixture::new();
        let root = fixture.root();
        // Expected values were obtained from glob's minimatch ignore options.
        for (pattern, path, ignored) in [
            ("./private.json", "private.json", true),
            ("{a..c}.json", "b.json", true),
            ("{a,b}.json", "b.json", true),
            ("#private.json", "#private.json", true),
            ("*.json", ".secret.json", true),
            ("**/node_modules/**", "node_modules/x", true),
            ("**/node_modules/**", "a/node_modules/x", true),
            ("!private.json", "private.json", false),
            ("!private.json", "!private.json", true),
            ("!(private).json", "public.json", true),
            ("!(private).json", "private.json", false),
            ("**/x", "x", true),
            ("*.json", "a/x.json", false),
            ("{3..1}.json", "2.json", true),
            ("{a..a}.json", "a.json", true),
            ("dir", "dir/x", false),
        ] {
            let file = fixture.0.join("public").join(path);
            std::fs::create_dir_all(file.parent().unwrap()).unwrap();
            std::fs::write(file, "fixture").unwrap();
            assert_eq!(
                open(&root, &format!("/{path}"), &[pattern.to_owned()]).is_none(),
                ignored,
                "pattern={pattern:?} path={path:?}"
            );
        }
    }
    #[test]
    fn fixture_paths_cannot_escape_the_retained_public_directory() {
        let fixture = Fixture::new();
        let root = fixture.root();
        let cases: serde_json::Value = serde_json::from_str(include_str!(
            "../../../../conformance/hosting-fixtures/security.json"
        ))
        .unwrap();
        symlink("../outside.txt", &fixture.0.join("public/outside-link.txt"));
        for case in cases["cases"].as_array().unwrap() {
            assert!(
                open(&root, case["path"].as_str().unwrap(), &[]).is_none(),
                "{}",
                case["id"]
            );
        }
        for path in [
            "/C:outside.txt",
            "/C:/outside.txt",
            "/\\\\server\\outside.txt",
            "/safe.txt:stream",
        ] {
            assert!(open(&root, path, &[]).is_none(), "{path}");
        }
        symlink("safe.txt", &fixture.0.join("public/inside-link.txt"));
        assert!(open(&root, "/inside-link.txt", &[]).is_some());
        symlink("cycle-b", &fixture.0.join("public/cycle-a"));
        symlink("cycle-a", &fixture.0.join("public/cycle-b"));
        assert!(open(&root, "/cycle-a", &[]).is_none());
        std::fs::write(fixture.0.join("public/%2e%2e"), "literal percent").unwrap();
        assert!(
            open(&root, "/%252e%252e", &[]).is_some(),
            "decode exactly once"
        );
    }
    #[test]
    fn ignored_paths_and_symlink_targets_are_absent() {
        let fixture = Fixture::new();
        let root = fixture.root();
        symlink("safe.txt", &fixture.0.join("public/alias.txt"));
        let ignore = vec!["safe.txt".to_owned()];
        assert!(open(&root, "/safe.txt", &ignore).is_none());
        assert!(open(&root, "/alias.txt", &ignore).is_none());
        assert!(open(&root, "/alias.txt", &[]).is_some());
        std::fs::create_dir(fixture.0.join("public/.hidden")).unwrap();
        std::fs::write(fixture.0.join("public/.hidden/file"), "hidden").unwrap();
        assert!(open(&root, "/.hidden/file", &["**/.*".to_owned()]).is_some());
        assert!(open(&root, "/.hidden/file", &[]).is_some());
        std::fs::create_dir_all(fixture.0.join("public/nested/node_modules/pkg")).unwrap();
        std::fs::write(
            fixture.0.join("public/nested/node_modules/pkg/file.js"),
            "module",
        )
        .unwrap();
        assert!(open(
            &root,
            "/nested/node_modules/pkg/file.js",
            &["**/node_modules/**".to_owned()]
        )
        .is_none());
        assert!(open(&root, "/safe.txt", &["*.json".to_owned()]).is_some());
    }
    #[test]
    fn replacement_after_open_cannot_change_the_object_used_for_the_body() {
        let fixture = Fixture::new();
        let root = fixture.root();
        let mut asset = open(&root, "/safe.txt", &[]).unwrap();
        let replaced = std::fs::rename(
            fixture.0.join("public/safe.txt"),
            fixture.0.join("public/old.txt"),
        );
        if replaced.is_ok() {
            symlink("../outside.txt", &fixture.0.join("public/safe.txt"));
            assert!(open(&root, "/safe.txt", &[]).is_none());
        }
        let mut text = String::new();
        asset.file.read_to_string(&mut text).unwrap();
        assert_eq!(text, "safe fixture");
        assert_eq!(asset.bytes, 12);
    }
    #[cfg(unix)]
    #[test]
    fn a_fifo_does_not_block_before_the_regular_file_check() {
        let fixture = Fixture::new();
        let root = fixture.root();
        let status = std::process::Command::new("mkfifo")
            .args(["-m", "600"])
            .arg(fixture.0.join("public/pipe"))
            .status()
            .expect("the Unix mkfifo utility must be available");
        assert!(status.success(), "FIFO fixture creation must succeed");
        assert!(open(&root, "/pipe", &[]).is_none());
    }
    #[cfg(windows)]
    #[test]
    fn an_outside_directory_junction_is_not_a_serving_capability() {
        let fixture = Fixture::new();
        let root = fixture.root();
        let junction = fixture.0.join("public").join("junction");
        let status = std::process::Command::new("cmd")
            .args(["/C", "mklink", "/J"])
            .arg(&junction)
            .arg(&fixture.0)
            .status()
            .unwrap();
        assert!(
            status.success(),
            "native junction setup must succeed before this test can pass"
        );
        assert!(open(&root, "/junction/outside.txt", &[]).is_none());
        drop(root);
        std::fs::remove_dir(junction).unwrap();
    }
}

#[cfg(test)]
mod decoder_tests {
    use super::decode_uri;

    #[test]
    fn uri_decoding_preserves_reserved_spelling_plus_and_one_decode() {
        for (input, expected) in [
            ("a+b", "a+b"),
            ("%2f%2F%3a%3A%3f%3F", "%2f%2F%3a%3A%3f%3F"),
            (
                "%3B%2F%3F%3A%40%26%3D%2B%24%2C%23",
                "%3B%2F%3F%3A%40%26%3D%2B%24%2C%23",
            ),
            ("%252f%255c", "%2f%5c"),
            ("%25%20%5c%00", "% \\\0"),
            ("caf%C3%A9/%E6%97%A5", "café/日"),
            ("literal日+%20end", "literal日+ end"),
        ] {
            assert_eq!(decode_uri(input).as_deref(), Some(expected), "{input}");
        }
    }

    #[test]
    fn malformed_escapes_and_invalid_utf8_are_refused_without_lossy_replacement() {
        for input in [
            "%",
            "%2",
            "%2G",
            "%+f",
            "%-1",
            "a%zzb",
            "%80",
            "%C0%AF",
            "%ED%A0%80",
            "%F4%90%80%80",
            "%C3",
        ] {
            assert_eq!(decode_uri(input), None, "{input}");
        }
    }
}

#[cfg(test)]
mod streaming_tests {
    use super::*;
    use http_body_util::BodyExt;
    #[tokio::test]
    async fn a_large_asset_is_streamed_in_bounded_frames() {
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path =
            std::env::temp_dir().join(format!("hosting-stream-{}-{stamp}", std::process::id()));
        std::fs::create_dir(&path).unwrap();
        let file = std::fs::File::create(path.join("large.bin")).unwrap();
        file.set_len(16 * 1024 * 1024).unwrap();
        drop(file);
        let root = cap_std::fs::Dir::open_ambient_dir(&path, cap_std::ambient_authority()).unwrap();
        let asset = open(&root, "/large.bin", &[]).unwrap();
        assert_eq!(asset.bytes, 16 * 1024 * 1024);
        let mut body = FileBody::new(asset.file, asset.bytes);
        for _ in 0..2 {
            let frame = body.frame().await.unwrap().unwrap().into_data().unwrap();
            assert!(
                !frame.is_empty() && frame.len() <= 1024 * 1024,
                "a frame must not buffer the entire asset"
            );
        }
        assert!(!hyper::body::Body::is_end_stream(&body));
        drop(body);
        drop(root);
        std::fs::remove_dir_all(path).unwrap();
    }
}
