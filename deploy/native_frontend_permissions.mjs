import { existsSync, lstatSync, readdirSync, realpathSync } from "node:fs";
import { dirname, join, relative, sep } from "node:path";

export function packagePermissions(root, {
  serviceUid, serviceGid, packageUid = 0, ancestorFloor = "/",
}) {
  if (!Number.isSafeInteger(serviceUid) || !Number.isSafeInteger(serviceGid) ||
      realpathSync(root) !== root) return false;
  const cache = join(root, ".next", "cache");
  if (!existsSync(cache)) return false;
  const cacheInfo = lstatSync(cache);
  if (!cacheInfo.isDirectory() || cacheInfo.uid !== serviceUid || cacheInfo.gid !== serviceGid ||
      (cacheInfo.mode & 0o777) !== 0o700) return false;
  function inspect(path) {
    const info = lstatSync(path);
    if (path === cache) {
      return info.isDirectory() && info.uid === serviceUid && info.gid === serviceGid &&
        (info.mode & 0o777) === 0o700;
    }
    if (info.isSymbolicLink()) {
      if (info.uid !== packageUid) return false;
      const actual = realpathSync(path);
      const tail = relative(root, actual);
      const cacheTail = relative(cache, actual);
      return tail !== ".." && !tail.startsWith(`..${sep}`) &&
        cacheTail !== "" && (cacheTail === ".." || cacheTail.startsWith(`..${sep}`));
    }
    if (info.uid !== packageUid || (info.mode & 0o222)) return false;
    if (info.isFile()) return Boolean(info.mode & 0o004);
    if (!info.isDirectory() || (info.mode & 0o005) !== 0o005) return false;
    return readdirSync(path).every((name) => inspect(join(path, name)));
  }
  for (let parent = dirname(root); ; parent = dirname(parent)) {
    const info = lstatSync(parent);
    if (!info.isDirectory() || info.uid !== packageUid || (info.mode & 0o022) ||
        (info.mode & 0o005) !== 0o005) return false;
    if (parent === ancestorFloor) break;
    if (parent === dirname(parent)) return false;
  }
  return inspect(root);
}
