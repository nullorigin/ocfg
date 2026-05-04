// Simple integration test for ocfg-macros

use ocfg_macros::{paste_str, uciname, dbg_here, dbg_loc, dbg_ctx};

#[test]
fn test_paste_str() {
    let s = paste_str!((hello world));
    assert_eq!(s, "helloworld");

    let s2 = paste_str!([snake]"HelloWorld");
    assert_eq!(s2, "hello_world");

    let s3 = paste_str!([pascal]"my_field" Getter);
    assert_eq!(s3, "MyFieldGetter");
}

#[test]
fn test_uciname() {
    let name = uciname!(wireless, radio0);
    assert_eq!(name, "wireless.radio0");

    let name2 = uciname!(network, lan, ipaddr);
    assert_eq!(name2, "network.lan.ipaddr");

    let name3 = uciname!(firewall);
    assert_eq!(name3, "firewall");
}

#[test]
fn test_dbg_macros() {
    // These macros should compile and run without panicking
    let _loc = dbg_loc!();
    let _ctx = dbg_ctx!();
    dbg_here!("test point");
}

#[test]
fn test_case_transformations() {
    // Test case transformation functions indirectly through paste_str
    assert_eq!(paste_str!([snake]"HelloWorld"), "hello_world");
    assert_eq!(paste_str!([screaming]"HelloWorld"), "HELLO_WORLD");
    assert_eq!(paste_str!([camel]"hello_world"), "helloWorld");
    assert_eq!(paste_str!([pascal]"hello_world"), "HelloWorld");
    assert_eq!(paste_str!([lower]"HelloWorld"), "helloworld");
    assert_eq!(paste_str!([upper]"HelloWorld"), "HELLOWORLD");
}



