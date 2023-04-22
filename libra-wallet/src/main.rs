pub mod legacy;

use clap::{Args, Parser, Subcommand};
use std::path::PathBuf;
use legacy::helpers::get_keys_from_prompt;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
#[command(propagate_version = true)]
struct Entry {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// New Mnemonic
    Seed,
    /// Use the legacy key derivation scheme
    Bip(KeyArgs),
    /// Use the legacy key derivation scheme
    Legacy(KeyArgs),
}

#[derive(Args, Debug)]
struct KeyArgs {
    ///  display private keys and authentication keys
    #[arg(short, long)]
    display: bool,
    #[arg(short, long)]
    /// save legacy keyscheme private keys to file
    output_path: Option<PathBuf>,

}

fn main() -> anyhow::Result<()>{
    let cli = Entry::parse();

    // You can check for the existence of subcommands, and if found use their
    // matches just as you would the top level cmd
    match &cli.command {
        Commands::Legacy(args) => {
            if !args.display && args.output_path.is_none() {
                println!("pass --display to show keys and/or --output-path to save keys");
                return Ok(());
            }
            let l = get_keys_from_prompt()?;
            if let Some(dir) = &args.output_path {
                l.save_keys(dir)?;
            }

            if args.display {
                l.display();
            }
        },
        Commands::Seed => println!("Seed"),
        Commands::Bip(args) => {
            println!("'wallet Bip' was used, name is: {:?}", args)
        },
        // _ => println!("No subcommand was used"),
    }
    Ok(())
}