import * as vscode from 'vscode';

// /*
//  * This function is used to override the default hover behavior in the debugger.
//  * It is used to provide a custom hover behavior for the debugger.
//  */
// export function overrideDebugHover(context: vscode.ExtensionContext) {
// 	// This is how mock debug hover works
// 	// FIXME: This is not working
// 	// context.subscriptions.push(vscode.languages.registerEvaluatableExpressionProvider('markdown', {
// 	// 	provideEvaluatableExpression(document: vscode.TextDocument, position: vscode.Position): vscode.ProviderResult<vscode.EvaluatableExpression> {

// 	// 		const VARIABLE_REGEXP = /\$[a-z][a-z0-9]*/ig;
// 	// 		const line = document.lineAt(position.line).text;

// 	// 		let m: RegExpExecArray | null;
// 	// 		while (m = VARIABLE_REGEXP.exec(line)) {
// 	// 			const varRange = new vscode.Range(position.line, m.index, position.line, m.index + m[0].length);

// 	// 			if (varRange.contains(position)) {
// 	// 				return new vscode.EvaluatableExpression(varRange);
// 	// 			}
// 	// 		}
// 	// 		return undefined;
// 	// 	}
// 	// }));
// }

// /*
//  * This function is used to override the default inline values behavior in the debugger.
//  * It is used to provide a custom inline values behavior for the debugger.
//  */
// export function overrideInlineValues(context: vscode.ExtensionContext) {
// 	// This is how mock inline values work
// 	// FIXME: This is not working
// 	// context.subscriptions.push(vscode.languages.registerInlineValuesProvider('markdown', {

// 	// 	provideInlineValues(document: vscode.TextDocument, viewport: vscode.Range, context: vscode.InlineValueContext) : vscode.ProviderResult<vscode.InlineValue[]> {

// 	// 		const allValues: vscode.InlineValue[] = [];

// 	// 		for (let l = viewport.start.line; l <= context.stoppedLocation.end.line; l++) {
// 	// 			const line = document.lineAt(l);
// 	// 			var regExp = /\$([a-z][a-z0-9]*)/ig;	// variables are words starting with '$'
// 	// 			do {
// 	// 				var m = regExp.exec(line.text);
// 	// 				if (m) {
// 	// 					const varName = m[1];
// 	// 					const varRange = new vscode.Range(l, m.index, l, m.index + varName.length);

// 	// 					// some literal text
// 	// 					//allValues.push(new vscode.InlineValueText(varRange, `${varName}: ${viewport.start.line}`));

// 	// 					// value found via variable lookup
// 	// 					allValues.push(new vscode.InlineValueVariableLookup(varRange, varName, false));

// 	// 					// value determined via expression evaluation
// 	// 					//allValues.push(new vscode.InlineValueEvaluatableExpression(varRange, varName));
// 	// 				}
// 	// 			} while (m);
// 	// 		}

// 	// 		return allValues;
// 	// 	}
// 	// }));
// }

/**
 * Converts a file path to a vscode Uri.
 * If the path is a valid file path, it returns a Uri using `vscode.Uri.file()`.
 * If the path is not a valid file path, it returns a Uri using `vscode.Uri.parse()`.
 * @param path - The file path to convert.
 * @returns A vscode Uri representing the file path.
 */
export function pathToUri(path: string) {
    try {
        return vscode.Uri.file(path);
    } catch (e) {
        return vscode.Uri.parse(path);
    }
}