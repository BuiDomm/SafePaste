export function hasFlag(args: string[], flag: string): boolean {
  return args.includes(flag);
}

export function option(args: string[], name: string): string | undefined {
  const inline = args.find((arg) => arg.startsWith(`${name}=`));
  if (inline) {
    return inline.slice(name.length + 1);
  }
  const index = args.indexOf(name);
  if (index >= 0) {
    const value = args[index + 1];
    if (!value || value.startsWith("--")) {
      throw new Error(`${name} requires a value`);
    }
    return value;
  }
  return undefined;
}

export function positionals(args: string[]): string[] {
  const result: string[] = [];
  for (let index = 0; index < args.length; index += 1) {
    const value = args[index]!;
    if (value.startsWith("--")) {
      if (!value.includes("=") && ["--format", "--mode", "--config", "--upstream", "--host", "--port"].includes(value)) {
        index += 1;
      }
      continue;
    }
    result.push(value);
  }
  return result;
}
