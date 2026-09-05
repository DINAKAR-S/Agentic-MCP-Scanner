// Deliberately vulnerable command runner: the shapes behind CVE-2025-53355,
// CVE-2025-53967, CVE-2026-0755 and CVE-2025-68144.

import { execSync, spawn, execFile } from "child_process";

export function scale(name: string, replicas: number): string {
  // A template literal is a shell string; the caller owns `name`.
  return execSync(`kubectl scale deployment ${name} --replicas=${replicas}`).toString();
}

export function runTool(cmd: string, args: string[]) {
  // shell: true re-introduces the shell that the argument array avoided.
  return spawn(cmd, args, { cwd: process.cwd(), shell: true });
}

export function gitLog(target: string, cb: (err: Error | null, out: string) => void) {
  // A target such as "--output=/tmp/x" is read by git as an option.
  execFile("git", ["log", "--oneline", target], (err, stdout) => cb(err, stdout));
}
