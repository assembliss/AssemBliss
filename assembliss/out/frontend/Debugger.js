"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.workspaceFileAccessor = exports.initialize = void 0;
const vscode = require("vscode");
const utils = require("./utils");
const Qdb_1 = require("./Qdb");
function initialize(context) {
    console.log('Initializing Assembliss extension.');
    //throw new Error('Function not implemented.');
    // register a configuration provider for 'qdb' debug type
    const provider = new ConfigurationProvider();
    context.subscriptions.push(vscode.debug.registerDebugConfigurationProvider('qdb', provider));
    console.log('Added configuration provider for qdb debug type.');
    context.subscriptions.push(vscode.commands.registerCommand('assembliss.runEditorContents', (resource) => {
        let targetResource = resource; // targetResource is the file to be run
        if (!targetResource && vscode.window.activeTextEditor) { // if there is no targetResource and there is an active text editor
            targetResource = vscode.window.activeTextEditor.document.uri; // set the targetResource to the active text editor's document uri
        }
        if (targetResource) { // if there is a targetResource
            vscode.debug.startDebugging(undefined, {
                type: 'qdb',
                name: 'Assembliss: Run File',
                request: 'launch',
                target: targetResource.fsPath
            }, { noDebug: true } // noDebug is set to true so that the debugger does not stop at the first line of the program
            );
        }
    }), vscode.commands.registerCommand('assembliss.debugEditorContents', (resource) => {
        let targetResource = resource;
        if (!targetResource && vscode.window.activeTextEditor) {
            targetResource = vscode.window.activeTextEditor.document.uri;
        }
        if (targetResource) {
            vscode.debug.startDebugging(undefined, {
                type: 'qdb',
                name: 'Assembliss: Debug File',
                request: 'launch',
                target: targetResource.fsPath,
                stopOnEntry: true
            });
        }
    }));
    console.log('Added commands for running and debugging editor contents.');
    // register a command that asks for a program name
    vscode.commands.registerCommand('assembliss.getProgramName', async (config) => {
        const program = await vscode.window.showInputBox({
            placeHolder: 'Please enter the name of an arm assembly file in the workspace folder'
        });
        console.log('Program selected: ' + program);
        return program;
    });
    console.log('Added command for getting program name.');
    // register a dynamic configuration provider for 'qdb' debug type
    context.subscriptions.push(vscode.debug.registerDebugConfigurationProvider('qdb', {
        provideDebugConfigurations(folder) {
            const config = [
                {
                    name: "Assembliss: Dynamic Launch",
                    request: "launch",
                    type: "qdb",
                    target: "${file}"
                }
            ];
            console.log('Dynamic configuration provided. Target: ' + config[0].target);
            return config;
        }
    }, vscode.DebugConfigurationProviderTriggerKind.Dynamic));
    console.log('Added dynamic configuration provider for qdb debug type.');
    let factory = new DebugAdapterFactory(); // This is where the debug adapter is created
    context.subscriptions.push(vscode.debug.registerDebugAdapterDescriptorFactory('qdb', factory));
    // Checks if the factory object has a dispose method. 
    // The dispose method is a convention in VSCode extensions for cleaning up resources. 
    // If the factory object can be disposed of, it's added to the context subscriptions as well. 
    // This ensures that the factory's dispose method will be called when the extension is deactivated, 
    // allowing the factory to clean up its resources.
    if ('dispose' in factory) {
        context.subscriptions.push(factory);
    }
    console.log('Added debug adapter descriptor factory for qdb debug type.');
    // utils.overrideDebugHover(context); // This is used to override the default hover behavior in the debugger. This is a stretch goal.
    // utils.overrideInlineValues(context); // This is used to override the default inline values behavior in the debugger. This is a stretch goal.
}
exports.initialize = initialize;
/**
 * This is used to provide the initial configuration for the debugger if launch.json is missing or empty.
 */
class ConfigurationProvider {
    /**
     * Massage a debug configuration just before a debug session is being launched,
     * e.g. add all missing attributes to the debug configuration.
     */
    resolveDebugConfiguration(folder, config, token) {
        // if launch.json is missing or empty
        if (!config.type && !config.request && !config.name) {
            const editor = vscode.window.activeTextEditor;
            if (editor && editor.document.languageId === 'arm64') {
                config.type = 'qdb';
                config.name = 'Assembliss: Launch Resolve';
                config.request = 'launch';
                config.target = '${file}';
                config.stopOnEntry = true;
            }
        }
        if (!config.target) {
            return vscode.window.showInformationMessage("Cannot find a program to debug").then(_ => {
                return undefined; // abort launch
            });
        }
        return config;
    }
}
/**
 * File accessor for workspace files.
 */
exports.workspaceFileAccessor = {
    isWindows: typeof process !== 'undefined' && process.platform === 'win32',
    /**
     * Reads the contents of a file asynchronously.
     * @param path - The path of the file to read.
     * @returns A promise that resolves to the file contents as a Uint8Array.
     */
    async readFile(path) {
        let uri;
        try {
            uri = utils.pathToUri(path);
        }
        catch (e) {
            return new TextEncoder().encode(`cannot read '${path}'`);
        }
        return await vscode.workspace.fs.readFile(uri);
    },
    /**
     * Writes the contents to a file asynchronously.
     * @param path - The path of the file to write.
     * @param contents - The contents to write as a Uint8Array.
     */
    async writeFile(path, contents) {
        await vscode.workspace.fs.writeFile(utils.pathToUri(path), contents);
    }
};
/**
 * An implementation of a debug adapter descriptor factory that uses an inline implementation of a debug adapter.
 */
class DebugAdapterFactory {
    createDebugAdapterDescriptor(_session) {
        let assembliss = new Qdb_1.AssemblissDebugSession(exports.workspaceFileAccessor);
        return new vscode.DebugAdapterInlineImplementation(assembliss);
    }
}
//# sourceMappingURL=Debugger.js.map