// The module 'vscode' contains the VS Code extensibility API
// Import the module and reference it with the alias vscode in your code below
import * as vscode from 'vscode';
import * as DebuggerExtension from './Debugger/Debugger';

// this method is called when your extension is activated
// your extension is activated the very first time the command is executed
export async function activate(context: vscode.ExtensionContext) {
  // Use the console to output diagnostic information (console.log) and errors (console.error)
  // This line of code will only be executed once when your extension is activated
  console.log('Extension "Assembliss" is now active.');

  let disposable = vscode.commands.registerCommand('assembliss.helloWorld', () => {
		// The code you place here will be executed every time your command is executed

		// Display a message box to the user
		vscode.window.showInformationMessage('Hello World!');
	});

	context.subscriptions.push(disposable);
  // The command has been defined in the package.json file
  // Now provide the implementation of the command with registerCommand
  // The commandId parameter must match the command field in package.json

    // Initialize the DebuggerExtension and register the related commands and providers.
    await DebuggerExtension.initialize(context); // await is used to wait for the promise to resolve before continuing execution.

    console.log('Assembliss extension has finished initializing.');
}

// this method is called when your extension is deactivated
export function deactivate() {
}

