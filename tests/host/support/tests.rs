use super::*;

#[test]
fn cargo_artifact_layouts_preserve_target_and_profile() {
    for profile in ["C:/project/target/release", "C:/cache/i686-pc-windows-msvc/release", "C:/cache/aarch64-pc-windows-msvc/custom-profile"] {
        let profile = Path::new(profile);
        for relative in ["deps/host-hash.exe", "build/br3k-host-tests/hash/out/host-hash.exe"] {
            assert_eq!(cargo_profile_dir(&profile.join(relative)), Some(profile));
        }
    }
    for path in ["C:/relocated/host.exe", "C:/relocated/package/hash/out/host.exe", "out/host.exe"] {
        assert_eq!(cargo_profile_dir(Path::new(path)), None);
    }
}
