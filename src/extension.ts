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
import * as vscode from 'vscode';
import * as DebuggerExtension from './frontend/Debugger';
import * as assemblerCommands from './AssemblerLinker/assemblerCommands';

// this method is called when your extension is activated
export async function activate(context: vscode.ExtensionContext) {
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

