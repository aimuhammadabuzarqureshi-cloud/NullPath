#[test]
fn test_ephemeral_key_reuse_compile_fail() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/compile_tests/ephemeral_key_reuse.rs");
}
