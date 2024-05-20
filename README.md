# AssemBliss

AssemBliss is a Visual Studio Code extension designed to streamline the assembly programming process by providing tools for assembling, linking, debugging, and executing assembly code. Developed by a senior design group at North Carolina State University, this extension is a handy tool for developers working with ARM assembly code.

## Getting Started

### Prerequisites

Before you can use AssemBliss, you need to install the following software on your computer:

- Visual Studio Code
- Node.js and TypeScript
- Python 3.11 and pip
- ARM GNU Toolchain for AArch64
- Qiling Framework

Run the following commands to install additional required packages:

```bash
sudo apt update
sudo apt install node-typescript -y
sudo apt install binutils-aarch64-linux-gnu -y
sudo apt install python3 -y
sudo apt upgrade python3-pip -y
pip3 install qiling
```

## Features

- **Loading, Editing, and Saving**: Directly manage assembly files within VS Code.
- **Assembling and Linking**: Integrate with ARM GNU toolchain to assemble and link files.
- **Execution**: Run assembled files directly within the IDE.
- **Debugging**: Use the Qiling framework for detailed debugging, including breakpoints and step execution.

## Developer Guide

### Setup Environment

For development, it's recommended to use Kali Linux (Release: 2024.1, Kernel: Linux 6.6.15-amd64) for compatibility. Here is how to set up your environment:

1. Install VS Code and Git.
2. Install Python 3.11.
3. Ensure all dependencies and toolchains are installed as listed in the prerequisites section.

### Architecture

AssemBliss consists of several components:

- **Assembler & Linker**: Located at `/assembliss/src/AssemblerLinker`, handles the assembly and linking of ARM files.
- **Runner and Debugger Backend**: Located at `/assembliss/src/backend`, manages the execution and debugging backend processes.
- **Debugger Frontend**: Integrates with VS Code to provide a seamless debugging experience.

### Running the Extension

When the extension is installed or running in an extension development host, the extension will automatically deploy when an assembly file is open or a debugging session is initiated.

### Using AssemBliss

#### Loading, Editing, and Saving Assembly Files

1. **Loading an Assembly File**
   - Click on the "Explorer" icon on the left-hand side of VS Code.
   - Click "Open Folder" and navigate to your assembly file.
   - Select the file to load it into VS Code.

2. **Editing an Assembly File**
   - Once loaded, the AssemBliss extension will automatically detect the file and allow editing in the text editor.

3. **Saving an Assembly File**
   - To save changes, press `Ctrl + S` (or `Cmd + S` on Mac).

#### Assembling and Linking an Assembly File

1. To assemble and link, use the AssemBliss commands via the Command Palette (`Ctrl+Shift+P`).
   - Select "AssemBliss: AS" to assemble the file.
   - Select "AssemBliss: LD" to link the assembled file.

#### Executing an Assembly File

1. To execute the assembled and linked file:
   - Open the Command Palette and select "AssemBliss: Run Editor Contents".

#### Debugging an Assembly File

1. To debug:
   - Load and assemble your file as described.
   - Set breakpoints and then run "AssemBliss: Debug Editor Contents" from the Command Palette.

   This will open the AssemBliss debug menu, displaying memory, CPU registers, and condition flags.


## Known Issues and Upgrades

- Condition flags and memory access are limited due to current backend capabilities.
- Plans to include Docker support for ease of setup and use.
- Plans to consolidate runtime and debug server into standalone debugger.

For more information and updates, visit [AssemBliss GitHub Repository](https://github.ncsu.edu/engr-csc-sdc/2024SpringTeam37-Batista).

## Authors

- Ivan Basora
- Samuel Burke
- Alex Chen ([ScraperMan2002](https://github.com/ScraperMan2002))
- Alex Field
- Willie Harris

## Acknowledgments

- Dr. Caio Batista de Melo, Project Supervisor
- CSC 492 Team 37
- North Carolina State University, Department of Computer Science

## License

This project is licensed under the Apache License, Version 2.0. See the [LICENSE](LICENSE) file for more information.
