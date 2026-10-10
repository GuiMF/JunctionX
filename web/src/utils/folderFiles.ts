// Relative paths are evidence labels only; no local filesystem paths are submitted.
const droppedPaths = new WeakMap<File, string>();

export function filePath(file: File): string {
  return droppedPaths.get(file) || file.webkitRelativePath || file.name;
}

export interface CollectedFiles {
  files: File[];
  issues: string[];
}

// Capture entries during the drop event: DataTransfer becomes unavailable afterwards.
export function collectDroppedFiles(transfer: DataTransfer): Promise<CollectedFiles> {
  const entries = Array.from(transfer.items ?? [])
    .filter(item => item.kind === 'file')
    .map(item => ({ entry: item.webkitGetAsEntry?.(), file: item.getAsFile() }));
  const fallback = Array.from(transfer.files);
  return (async () => {
    const result: CollectedFiles = { files: [], issues: [] };
    async function visit(entry: FileSystemEntry, parent = ''): Promise<void> {
      const path = `${parent}${entry.name}`;
      try {
        if (entry.isFile) {
          const file = await new Promise<File>((resolve, reject) => (entry as FileSystemFileEntry).file(resolve, reject));
          droppedPaths.set(file, path);
          result.files.push(file);
        } else if (entry.isDirectory) {
          const reader = (entry as FileSystemDirectoryEntry).createReader();
          // Browsers return directory entries in batches, not necessarily all at once.
          while (true) {
            const children = await new Promise<FileSystemEntry[]>((resolve, reject) => reader.readEntries(resolve, reject));
            if (!children.length) break;
            for (const child of children) await visit(child, `${path}/`);
          }
        }
      } catch {
        result.issues.push(`${path}: could not read this file or folder. Try Browse folder or check access.`);
      }
    }
    if (!entries.length) result.files.push(...fallback);
    for (const { entry, file } of entries) {
      if (entry) await visit(entry);
      else if (file) result.files.push(file);
    }
    return result;
  })();
}
