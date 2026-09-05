// The same runner as demo/vulnerable-2026/runner.ts with each defect fixed.

import { execFileSync, spawn, execFile } from "child_process";

export function scale(name: string, replicas: number): string {
  // An argument array, so nothing is parsed by a shell, and "--" so a name that
  // starts with "-" cannot be read as an option.
  if (name.startsWith("-")) throw new Error("refusing an option-shaped name");
  return execFileSync("kubectl", ["scale", "deployment", `--replicas=${replicas}`, "--", name]).toString();
}

export function runTool(cmd: string, args: string[]) {
  return spawn(cmd, args, { cwd: process.cwd() });
}

export function gitLog(target: string, cb: (err: Error | null, out: string) => void) {
  // "--" ends option parsing; a target starting with "-" is a path, not an option.
  execFile("git", ["log", "--oneline", "--", target], (err, stdout) => cb(err, stdout));
}
