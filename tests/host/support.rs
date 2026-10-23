use std::{env, fs, io, path::{Path, PathBuf}, process::{Child, Command, ExitStatus, Stdio}, thread, time::{Duration, Instant}};
use std::os::windows::process::CommandExt;

use serde::Serialize;
use tempfile::TempDir;
use windows_sys::Win32::System::Threading::CREATE_NO_WINDOW;

pub struct Case {
    directory: TempDir,
    bin_dir: PathBuf,
    timeout: Duration,
}

pub struct NativeTarget {
    child: ManagedChild,
    pub image: PathBuf,
}

#[derive(Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub struct ProcessConfig {
    pub process_id: u32,
}

#[derive(Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub struct ModuleConfig<'a> {
    pub process_id: u32,
    pub module_name: Option<&'a str>,
}

#[derive(Serialize)]
struct ScriptConfig<'a, T> {
    variables: &'a T,
}

fn script_config(variables: &impl Serialize) -> String {
    serde_yaml::to_string(&ScriptConfig { variables }).expect("serialize script config")
}

fn workspace() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap().parent().unwrap()
}

fn bin_dir() -> PathBuf {
    if let Some(path) = env::var_os("BR3K_TEST_BIN_DIR") {
        return std::path::absolute(path).expect("resolve BR3K_TEST_BIN_DIR");
    }
    // Cargo places integration-test executables in <profile>/deps for each target.
    let executable = env::current_exe().expect("locate host test executable");
    let deps = executable.parent().expect("test executable directory");
    assert_eq!(deps.file_name().unwrap(), "deps", "set BR3K_TEST_BIN_DIR for relocated test binaries");
    deps.parent().unwrap().to_owned()
}

impl Case {
    pub fn new() -> Self {
        assert!(!cfg!(debug_assertions), "host scenarios require release builds; use cargo test --release");
        let root = env::var_os("BR3K_TEST_OUTPUT_DIR").map(PathBuf::from)
            .unwrap_or_else(|| workspace().join("target/test-runs").join(env::consts::ARCH));
        let root = std::path::absolute(root).expect("resolve test output directory");
        fs::create_dir_all(&root).expect("create test output directory");
        let name = thread::current().name().unwrap_or("host").replace("::", "-");
        let directory = tempfile::Builder::new().prefix(&format!("{name}-")).tempdir_in(root).expect("create case directory");
        let seconds = env::var("BR3K_TEST_TIMEOUT").map(|value| value.parse::<u64>().expect("BR3K_TEST_TIMEOUT must be an integer"))
            .unwrap_or(180);
        assert!(seconds > 0, "BR3K_TEST_TIMEOUT must be positive");
        Self { directory, bin_dir: bin_dir(), timeout: Duration::from_secs(seconds) }
    }

    pub fn path(&self) -> &Path {
        self.directory.path()
    }

    fn binary(&self, name: &str) -> PathBuf {
        let path = self.bin_dir.join(name);
        assert!(path.is_file(), "missing release artifact: {}; build br3k-cli and br3k-test-fixtures first", path.display());
        path
    }

    pub fn run(&self, script: &str, variables: &impl Serialize) {
        let script = workspace().join(script);
        let invocation = tempfile::Builder::new().prefix(&format!("{}-", script.file_stem().unwrap().to_string_lossy()))
            .tempdir_in(self.path()).expect("create invocation directory").keep();
        let config = invocation.join("config.yaml");
        fs::write(&config, script_config(variables)).expect("write script config");
        let mut command = Command::new(self.binary("br3k-cli.exe"));
        command.args(["--script"]).arg(&script).arg("--config").arg(config).current_dir(self.path());
        let mut child = ManagedChild::spawn(&mut command, &invocation)
            .unwrap_or_else(|error| panic!("start CLI for {}: {error}", script.display()));
        let status = poll_until(self.timeout, || child.0.try_wait())
            .unwrap_or_else(|error| panic!("wait for CLI: {error}\n{}", diagnostics(&invocation)));
        // Close the CLI before reading logs or removing its working directory, including on timeout.
        drop(child);
        let status = status.unwrap_or_else(|| panic!("CLI timed out after {:?}\n{}", self.timeout, diagnostics(&invocation)));
        assert!(status.success(), "CLI exited with {status}\n{}", diagnostics(&invocation));
    }

    pub fn target(&self) -> NativeTarget {
        let image = self.path().join("native target.exe");
        fs::copy(self.binary("pe-target.exe"), &image).expect("copy native target");
        let logs = self.path().join("native-target");
        fs::create_dir(&logs).expect("create native target logs directory");
        let ready = logs.join("ready.txt");
        let mut command = Command::new(&image);
        command.arg("--idle").arg(&ready).current_dir(self.path());
        let mut child = ManagedChild::spawn(&mut command, &logs).expect("start native target");
        let pid = child.0.id().to_string();
        let result = poll_until(Duration::from_secs(10), || {
            if let Some(status) = child.0.try_wait()? {
                return Err(io::Error::other(format!("native target exited with {status}")));
            }
            match fs::read_to_string(&ready) {
                Ok(value) => Ok((value == pid).then_some(())),
                Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
                Err(error) => Err(error),
            }
        });
        assert!(matches!(result, Ok(Some(()))), "native target did not become ready: {result:?}\n{}", diagnostics(&logs));
        NativeTarget { child, image }
    }
}

impl Drop for Case {
    fn drop(&mut self) {
        if thread::panicking() {
            self.directory.disable_cleanup(true);
            eprintln!("Test artifacts retained: {}", self.path().display());
        }
    }
}

impl NativeTarget {
    pub fn pid(&self) -> u32 {
        self.child.0.id()
    }

    pub fn process_config(&self) -> ProcessConfig {
        ProcessConfig { process_id: self.pid() }
    }

    pub fn module_config<'a>(&self, name: Option<&'a str>) -> ModuleConfig<'a> {
        ModuleConfig { process_id: self.pid(), module_name: name }
    }

    pub fn name(&self) -> &str {
        self.image.file_name().unwrap().to_str().unwrap()
    }
}

struct ManagedChild(Child);

impl ManagedChild {
    fn spawn(command: &mut Command, logs: &Path) -> io::Result<Self> {
        command.stdin(Stdio::null())
            .stdout(fs::File::create(logs.join("stdout.log"))?)
            .stderr(fs::File::create(logs.join("stderr.log"))?)
            .creation_flags(CREATE_NO_WINDOW);
        command.spawn().map(Self)
    }
}

impl Drop for ManagedChild {
    fn drop(&mut self) {
        if !matches!(self.0.try_wait(), Ok(Some(_))) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
}

fn poll_until<T>(timeout: Duration, mut poll: impl FnMut() -> io::Result<Option<T>>) -> io::Result<Option<T>> {
    let started = Instant::now();
    loop {
        if let Some(result) = poll()? {
            return Ok(Some(result));
        }
        let remaining = timeout.saturating_sub(started.elapsed());
        if remaining.is_zero() {
            return Ok(None);
        }
        thread::sleep(remaining.min(Duration::from_millis(20)));
    }
}

fn diagnostics(directory: &Path) -> String {
    ["stdout.log", "stderr.log"].map(|name| {
        let path = directory.join(name);
        let output = fs::read(&path).map(|bytes| String::from_utf8_lossy(&bytes).into_owned()).unwrap_or_else(|error| error.to_string());
        format!("{}:\n{output}", path.display())
    }).join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::windows::process::ExitStatusExt;

    #[test]
    fn config_preserves_unicode_null_and_false() {
        #[derive(Serialize)]
        struct Variables<'a> {
            name: &'a str,
            empty: Option<u32>,
            enabled: bool,
        }
        let yaml = script_config(&Variables { name: "space and \u{41f}\u{440}\u{438}\u{432}\u{435}\u{442}", empty: None, enabled: false });
        assert!(!yaml.contains('\r'));
        let config: serde_yaml::Value = serde_yaml::from_str(&yaml).unwrap();
        assert_eq!(config["variables"]["name"].as_str(), Some("space and \u{41f}\u{440}\u{438}\u{432}\u{435}\u{442}"));
        assert!(config["variables"]["empty"].is_null());
        assert_eq!(config["variables"]["enabled"].as_bool(), Some(false));
    }

    #[test]
    fn completed_process_status_is_preserved() {
        for code in [0, 7] {
            let status = poll_until(Duration::ZERO, || Ok(Some(ExitStatus::from_raw(code)))).unwrap().unwrap();
            assert_eq!(status.code(), Some(code as i32));
        }
    }

    #[test]
    fn unfinished_process_hits_deadline() {
        let mut polls = 0;
        let result = poll_until::<ExitStatus>(Duration::ZERO, || {
            polls += 1;
            Ok(None)
        }).unwrap();
        assert!(result.is_none());
        assert_eq!(polls, 1);
    }
}
