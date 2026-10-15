type Edge = { id: string; source: string; target: string };
type Point = { x: number; y: number };

/** Separate bounded logical links without merging identities or implying causality. */
export function topologyEdgePaths(
  edges: readonly Edge[],
  positions: ReadonlyMap<string, Point>,
  spacing = 18,
  maxOffset = 80,
): Map<string, string> {
  const groups = new Map<string, Edge[]>();
  const result = new Map<string, string>();
  for (const edge of edges) {
    const source = positions.get(edge.source);
    const target = positions.get(edge.target);
    if (!source || !target || ![source.x, source.y, target.x, target.y].every(Number.isFinite)) continue;
    const key = JSON.stringify([edge.source, edge.target].sort());
    const group = groups.get(key) || [];
    group.push(edge);
    groups.set(key, group);
  }
  for (const group of groups.values()) {
    group.sort((left, right) => left.id < right.id ? -1 : left.id > right.id ? 1 : 0);
    const step = Math.min(spacing, 2 * maxOffset / Math.max(1, group.length - 1));
    group.forEach((edge, index) => {
      const source = positions.get(edge.source)!;
      const target = positions.get(edge.target)!;
      const [start, end] = edge.source <= edge.target ? [source, target] : [target, source];
      const dx = end.x - start.x, dy = end.y - start.y;
      const distance = Math.hypot(dx, dy);
      const offset = (index - (group.length - 1) / 2) * step;
      if (distance === 0) {
        const radius = 10 + (index + 1) * Math.min(8, maxOffset / group.length);
        result.set(edge.id, `M ${source.x} ${source.y} C ${source.x + radius} ${source.y - radius * 2} ${source.x - radius} ${source.y - radius * 2} ${target.x} ${target.y}`);
      } else if (offset === 0) {
        result.set(edge.id, `M ${source.x} ${source.y} L ${target.x} ${target.y}`);
      } else {
        const x = (start.x + end.x) / 2 - dy / distance * offset;
        const y = (start.y + end.y) / 2 + dx / distance * offset;
        result.set(edge.id, `M ${source.x} ${source.y} Q ${x} ${y} ${target.x} ${target.y}`);
      }
    });
  }
  return result;
}
