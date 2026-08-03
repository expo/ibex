import { canonicalJson } from './capsec-contract.mjs';
import { decodeCanonicalSourceId } from './authenticated-graph-snapshot.mjs';

const compareCanonical = (left, right) =>
  Buffer.from(canonicalJson(left)).compare(Buffer.from(canonicalJson(right)));

const orderedNodeEntries = (rows) => [...rows].sort(([left], [right]) =>
  Buffer.from(left).compare(Buffer.from(right)));

/**
 * Refuse any divergence between policy analysis and the native graph that is
 * the compiled producer's authority/packaging source of truth.
 * @ref LLP 0029#1-command-surface-and-producer-pipeline
 */
export function assertCompiledPolicyAnalysisMatchesNativeGraph({
  snapshot,
  expectedFileNodes,
  expectedPackages,
  expectedEntrySourceId,
  expectedEntryIntegrity,
  expectedCandidateSets,
}) {
  const observedFileNodes = new Map();
  for (const node of snapshot.nodes) {
    if (decodeCanonicalSourceId(node.sourceId).kind === 'file') {
      observedFileNodes.set(node.sourceId, node.sourceIntegrity);
    }
  }
  if (
    canonicalJson(orderedNodeEntries(observedFileNodes)) !==
    canonicalJson(orderedNodeEntries(expectedFileNodes))
  ) {
    throw new TypeError(
      'native authenticated graph file identities differ from the policy analysis bytes',
    );
  }
  if (
    canonicalJson([...snapshot.packages].sort(compareCanonical)) !==
    canonicalJson([...expectedPackages].sort(compareCanonical))
  ) {
    throw new TypeError(
      'native authenticated graph package inventory differs from policy analysis',
    );
  }
  if (
    snapshot.entry.sourceId !== expectedEntrySourceId ||
    observedFileNodes.get(snapshot.entry.sourceId) !== expectedEntryIntegrity
  ) {
    throw new TypeError(
      'native authenticated graph entry differs from the policy entry identity',
    );
  }
  const observedCandidateSets = snapshot.candidateSets.map((site) => ({
    requester: site.requester,
    label: site.label,
    candidates: site.candidates,
  })).sort(compareCanonical);
  if (
    canonicalJson(observedCandidateSets) !==
    canonicalJson([...expectedCandidateSets].sort(compareCanonical))
  ) {
    throw new TypeError(
      'native computed-candidate tables differ from the reviewed manifest materialization',
    );
  }
}
