"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.activateAssemblerCommands = void 0;
/*
 * Copyright 2024 Willie D. Harris, Jr., Dr. Caio Batista de Melo
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
const vscode = require("vscode");
const path = require("path");
/**
 *
 * @param {*} cmds commands to execute
 * @param {*} cwd working directory
 * @param {*} outputstream output window
 */
async function execsequence(cmds, cwd, outputstream) {
    outputstream.show();
    for (const cmd of cmds) {
        outputstream.sendText(cmd);
    }
}
function activateAssemblerCommands(context) {
    console.log('Adding assembler commands');
    const outputstream = vscode.window.createTerminal('Assembliss');
    const assembleCommand = vscode.commands.registerCommand('assembliss.AS', function () {
        const conf = vscode.workspace.getConfiguration('assembliss');
        const assemblerCommand = conf.assembler;
        vscode.window.showInformationMessage('Assembler from AssemBliss!');
        const workSpaceFolders = vscode.workspace.workspaceFolders;
        if (workSpaceFolders == undefined || workSpaceFolders.length < 1) {
            vscode.window.showWarningMessage('A workspace needs to be open');
        }
        else {
            //first workspace open
            const workingDirectory = workSpaceFolders[0].uri.fsPath;
            //pattern to find assembly files
            const pattern = new vscode.RelativePattern(workSpaceFolders[0], '**/*.{s,S,asm}');
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
                        return;
                    }
                    const cmdSeq = [];
                    //Assemble each file
                    files.forEach((fn) => {
                        //Command string for assembler
                        var objectFileName = fn.slice(0, -2);
                        //aarch64-linux-gnu-as
                        const cmd = `${assemblerCommand} ${fn} -g -o ${objectFileName}.obj`;
                        cmdSeq.push(cmd);
                    });
                    execsequence(cmdSeq, workingDirectory, outputstream);
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
        }
        else {
            //first workspace open
            const workingDirectory = workSpaceFolders[0].uri.fsPath;
            //pattern to find assembly files
            const pattern = new vscode.RelativePattern(workSpaceFolders[0], '**/*.{o,out,obj}');
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
                        return;
                    }
                    const cmdSeq = [];
                    //Assemble each file
                    files.forEach((fn) => {
                        //Command string for linker
                        var objectFileName = fn.slice(0, -4);
                        //aarch64-linux-gnu-ld
                        const cmd = `${linkerCommand} ${fn} -o ${objectFileName}`;
                        cmdSeq.push(cmd);
                    });
                    execsequence(cmdSeq, workingDirectory, outputstream);
                });
            });
        }
    });
    context.subscriptions.push(assembleCommand);
    context.subscriptions.push(linkCommand);
}
exports.activateAssemblerCommands = activateAssemblerCommands;
//# sourceMappingURL=assemblerCommands.js.map