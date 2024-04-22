import * as vscode from 'vscode';

import * as path from 'path';

// This method is called when your extension is activated
// Your extension is activated the very first time the command is executed

/**
 * 
 * @param {*} cmds commands to execute
 * @param {*} cwd working directory
 * @param {*} outputstream output window
 */
async function execsequence(cmds, cwd, outputstream) {
    outputstream.show();
    for (const cmd of cmds) {
        outputstream.sendText(cmd)
    }
}

export function activateAssemblerCommands(context: vscode.ExtensionContext) {
    console.log('Adding assembler commands');
    const outputstream = vscode.window.createTerminal('Assembliss');
	
	const assembleCommand = vscode.commands.registerCommand('assembliss.AS', function () {
		const conf = vscode.workspace.getConfiguration('assembliss');
        const assemblerCommand = conf.assembler;
		vscode.window.showInformationMessage('Assembler from AssemBliss!');
		const workSpaceFolders = vscode.workspace.workspaceFolders;
		if (workSpaceFolders == undefined || workSpaceFolders.length < 1) {
			vscode.window.showWarningMessage('A workspace needs to be open');
		} else {
		
			//first workspace open
			const workingDirectory = workSpaceFolders[0].uri.fsPath;
			//pattern to find assembly files
			const pattern = new vscode.RelativePattern(workSpaceFolders[0],'**/*.{s,S,asm}')
			//Find files that match pattern
			vscode.workspace.findFiles(pattern).then((filepaths) => {
				const filelist = filepaths.map((uri) => {
					return path.relative(workSpaceFolders[0].uri.toString(), uri.toString());
				});
				vscode.window.showQuickPick(filelist, {
					canPickMany: true
				}).then((files) => {
					if (files === undefined || files.length < 1) {
						vscode.window.showWarningMessage('Select one or more file');
						return
					}
					const cmdSeq: string[] = [];

					//Assemble each file
					files.forEach((fn) => {
						//Command string for assembler
						var objectFileName = fn.slice(0,-2)
						//aarch64-linux-gnu-as
						const cmd = `${assemblerCommand} ${fn} -g -o ${objectFileName}.obj`;
						cmdSeq.push(cmd)
					});

					execsequence(cmdSeq, workingDirectory, outputstream)
				});

			});
		}
	});

	const linkCommand = vscode.commands.registerCommand('assembliss.LD', function () {
		const conf = vscode.workspace.getConfiguration('assembliss');
        const linkerCommand = conf.linker;
		vscode.window.showInformationMessage('Linker from AssemBliss!');
		const workSpaceFolders = vscode.workspace.workspaceFolders;
		if (workSpaceFolders == undefined || workSpaceFolders.length < 1) {
			vscode.window.showWarningMessage('A workspace needs to be open');
		} else {
		
			//first workspace open
			const workingDirectory = workSpaceFolders[0].uri.fsPath;
			//pattern to find assembly files
			const pattern = new vscode.RelativePattern(workSpaceFolders[0],'**/*.{o,out,obj}')
			//Find files that match pattern
			vscode.workspace.findFiles(pattern).then((filepaths) => {
				const filelist = filepaths.map((uri) => {
					return path.relative(workSpaceFolders[0].uri.toString(), uri.toString());
				});
				vscode.window.showQuickPick(filelist, {
					canPickMany: true
				}).then((files) => {
					if (files === undefined || files.length < 1) {
						vscode.window.showWarningMessage('Select one or more file');
						return
					}
					const cmdSeq: string[] = [];

					//Assemble each file
					files.forEach((fn) => {
						//Command string for linker
						var objectFileName = fn.slice(0,-4)
						//aarch64-linux-gnu-ld
						const cmd = `${linkerCommand} ${fn} -o ${objectFileName}`;
						cmdSeq.push(cmd)
					});

					execsequence(cmdSeq, workingDirectory, outputstream)
				});

			});
		}
	});

	context.subscriptions.push(assembleCommand);
	context.subscriptions.push(linkCommand);
}