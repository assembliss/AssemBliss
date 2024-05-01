// The module 'vscode' contains the VS Code extensibility API
// Import the module and reference it with the alias vscode in your code below
import * as vscode from 'vscode';
import * as DebuggerExtension from './frontend/Debugger';
import * as assemblerCommands from './AssemblerLinker/assemblerCommands';

// this method is called when your extension is activated
// your extension is activated the very first time the command is executed
export async function activate(context: vscode.ExtensionContext) {
  // Use the console to output diagnostic information (console.log) and errors (console.error)
  // This line of code will only be executed once when the extension is activated
  console.log('Extension "Assembliss" is now active.');

  // Register the assembler commands
  assemblerCommands.activateAssemblerCommands(context);

  // Initialize the DebuggerExtension and register the related commands and providers.
  await DebuggerExtension.initialize(context); // await is used to wait for the promise to resolve before continuing execution.
  console.log('Assembliss extension has finished initializing.');
}

// this method is called when your extension is deactivated
export function deactivate() {
}

