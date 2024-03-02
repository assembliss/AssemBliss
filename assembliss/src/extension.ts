'use strict';
import * as vscode from 'vscode';
// Assuming QilingEmulator is a class you have defined for handling Qiling emulation
import { QilingEmulator } from './QilingEmulator';

// this method is called when your extension is activated
// your extension is activated the very first time the command is executed

export function activate(context: vscode.ExtensionContext) {
    console.log('Extension "qiling-armv8-emulator" is now active.');

    const config = vscode.workspace.getConfiguration('qiling');
    let archConfig = config.get('arch');
    let rootfsConfig = config.get('rootfs');
    let binaryConfig = config.get('binaryPath');

    let arch = archConfig ? archConfig.toString() : 'arm64';
    let rootfs = rootfsConfig ? rootfsConfig.toString() : '';
    let binaryPath = binaryConfig ? binaryConfig.toString() : '';

    let qilingEmulator = new QilingEmulator(arch, rootfs, binaryPath);

    let outputChannel = vscode.window.createOutputChannel('Qiling ARMv8');

    qilingEmulator.on('onInfoMessage', (msg: string) => {
        vscode.window.showInformationMessage('Qiling: ' + msg);
    });
    qilingEmulator.on('onWarningMessage', (msg: string) => {
        vscode.window.showWarningMessage('Qiling: ' + msg);
    });
    qilingEmulator.on('onErrorMessage', (msg: string) => {
        vscode.window.showErrorMessage('Qiling: ' + msg);
    });

    qilingEmulator.on('onEmulatorMessage', (data: string) => {
        outputChannel.append('Qiling> ');
        let lines = data.split('\\n');
        if (lines.length === 1) {
            lines = data.split('\n');
        }
        lines.forEach(line => {
            outputChannel.appendLine(line.trim());
        });
    });

    const getCode = () => {
        let textEditor = vscode.window.activeTextEditor;
        if (!textEditor) {
            return "";
        }
        let selection = textEditor.selection;
        let text = textEditor.document.getText(selection);
        if (textEditor.selection.isEmpty) {
            text = textEditor.document.lineAt(textEditor.selection.start.line).text;
        }
        return text;
    };

    let disposable = vscode.commands.registerCommand('extension.runQiling', () => {
        let code = getCode();
        if (code === '') {
            return;
        }
        qilingEmulator.runCode(code);
    });
    context.subscriptions.push(disposable);
}

// this method is called when your extension is deactivated
export function deactivate() {
}
