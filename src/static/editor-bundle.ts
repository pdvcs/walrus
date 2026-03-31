import { basicSetup } from "codemirror";
import { EditorView } from "@codemirror/view";
import { StreamLanguage } from "@codemirror/language";
import { toml } from "@codemirror/legacy-modes/mode/toml";

(globalThis as any).WalrusEditor = { basicSetup, EditorView, StreamLanguage, toml };
