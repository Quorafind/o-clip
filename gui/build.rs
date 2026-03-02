fn main() {
    println!("cargo:rerun-if-changed=o-clip-gui.rc");
    println!("cargo:rerun-if-changed=o-clip-gui.manifest");

    #[cfg(windows)]
    {
        embed_resource::compile("o-clip-gui.rc", embed_resource::NONE);
    }
}

