fn main() {
    #[cfg(not(feature = "colors"))]
    println!("Feature color is switched off");

    #[cfg(feature = "colors")]
    {
        use atty::Stream::{Stderr, Stdout};
        use yansi::{Color, Paint, Style};

        for i in 0..=255 {
            println!("{}: {}", i, Paint::fixed(i, i));
        }

        println!("");

        if atty::is(Stdout) {
            println!(
                "Stdout is considered a tty - \
                 flexi_logger::AdaptiveFormat will use colors",
            );
        } else {
            println!(
                "Stdout is not considered a tty - \
                 flexi_logger::AdaptiveFormat will NOT use colors"
            );
        }

        if atty::is(Stderr) {
            println!(
                "Stderr is considered a tty - \
                 flexi_logger::AdaptiveFormat will use colors",
            );
        } else {
            println!(
                "Stderr is not considered a tty - \
                 flexi_logger::AdaptiveFormat will NOT use colors!"
            );
        }

        // Enable ASCII escape sequence support on Windows consoles,
        // but disable coloring on unsupported Windows consoles
        if cfg!(windows) {
            if !Paint::enable_windows_ascii() {
                println!("unsupported windows console detected => coloring disabled");
                Paint::disable();
                return;
            }
        }

        println!(
            "\n{}",
            Style::new(Color::Fixed(196))
                .bold()
                .paint("This is red output like by default with err!")
        );
        println!(
            "{}",
            Style::new(Color::Fixed(208))
                .bold()
                .paint("This is yellow output like by default with warn!")
        );
        println!(
            "{}",
            Style::new(Color::Unset).paint("This is normal output like by default with info!")
        );
        println!(
            "{}",
            Style::new(Color::Fixed(7)).paint("This is output like by default with debug!")
        );
        println!(
            "{}",
            Style::new(Color::Fixed(8)).paint("This is grey output like by default with trace!")
        );
    }
}
