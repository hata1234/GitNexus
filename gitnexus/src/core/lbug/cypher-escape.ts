const CYPHER_LABEL_RE = /^[A-Za-z_][A-Za-z0-9_]*$/;

export const quoteCypherString = (value: unknown): string => {
  if (value === null || value === undefined) return 'NULL';
  return `'${String(value)
    .replace(/\\/g, '\\\\')
    .replace(/'/g, "''")
    .replace(/\r/g, '\\r')
    .replace(/\n/g, '\\n')}'`;
};

export const quoteCypherIdentifier = (identifier: string, force = false): string => {
  if (!force && CYPHER_LABEL_RE.test(identifier)) return identifier;
  return `\`${identifier.replace(/\`/g, '\`\`')}\``;
};
