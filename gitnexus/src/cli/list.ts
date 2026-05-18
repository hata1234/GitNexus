/**
 * List Command
 *
 * Shows all indexed repositories from the global registry.
 */

import { listRegisteredRepos } from '../storage/repo-manager.js';
import { isLocalRepoPathAllowed, writeSecurityAudit } from '../security/local-policy.js';

export const listCommand = async () => {
  const allEntries = await listRegisteredRepos({ validate: true });
  const entries = allEntries.filter((entry) => {
    const allowed = isLocalRepoPathAllowed(entry.path);
    if (!allowed) {
      writeSecurityAudit({
        type: 'cli-list-repo-scope-policy',
        repo: entry.name,
        path: entry.path,
        allowed,
        reason: 'repo-path-denylist',
      });
    }
    return allowed;
  });

  if (entries.length === 0) {
    console.log('No indexed repositories found.');
    console.log('Run `gitnexus analyze` in a git repo to index it.');
    return;
  }

  console.log(`\n  Indexed Repositories (${entries.length})\n`);

  // Count occurrences of each name so colliding entries can be
  // disambiguated in the header (#829). Unique-name entries render
  // identically to pre-#829 output; only collisions gain a suffix.
  const nameCounts = new Map<string, number>();
  for (const e of entries) {
    const key = e.name.toLowerCase();
    nameCounts.set(key, (nameCounts.get(key) ?? 0) + 1);
  }

  for (const entry of entries) {
    const indexedDate = new Date(entry.indexedAt).toLocaleString();
    const stats = entry.stats || {};
    const commitShort = entry.lastCommit?.slice(0, 7) || 'unknown';
    const hasCollision = (nameCounts.get(entry.name.toLowerCase()) ?? 0) > 1;
    const header = hasCollision ? `${entry.name}  (${entry.path})` : entry.name;

    console.log(`  ${header}`);
    console.log(`    Path:    ${entry.path}`);
    console.log(`    Indexed: ${indexedDate}`);
    console.log(`    Commit:  ${commitShort}`);
    console.log(
      `    Stats:   ${stats.files ?? 0} files, ${stats.nodes ?? 0} symbols, ${stats.edges ?? 0} edges`,
    );
    if (stats.communities) console.log(`    Clusters:   ${stats.communities}`);
    if (stats.processes) console.log(`    Processes:  ${stats.processes}`);
    console.log('');
  }
};
