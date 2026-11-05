# Agent Proof Network: witnessed blockchain checkpoints (research prototype)

This extension makes a batch of independently observed AI-agent action receipts
cryptographically tamper-evident. It is **not** a deployed chain service, a
production gateway or proof that an arbitrary agent is safe.

## Architecture

    Untrusted Codex / Agents SDK / LangGraph process
         -> operator-controlled MCP/HTTP execution gateway
         -> authenticated policy + target-side atomic authorization
         -> independently observed protected destination
         -> witness-controlled Ed25519 receipts and salted Merkle batches
         -> optional Base/Ethereum root anchoring
         -> external verifier (trusted key + inclusion + chain transaction)

**Only the gateway** should possess destination credentials. Sandboxed agents
must have no alternate egress to protected APIs. The witness owns its signing key,
private records and salts. Agent prompts, hooks and self-reported traces are
advisory and are not a security boundary.

### Codex integration (source examined)

Codex dispatches MCP calls via
https://github.com/openai/codex/blob/main/codex-rs/core/src/mcp_tool_call.rs
and supports shell execution through
https://github.com/openai/codex/blob/main/codex-rs/core/src/tools/handlers/unified_exec/exec_command.rs .
A dedicated remote MCP tool should expose only the narrow approved action.
Codex lifecycle PreToolUse/PostToolUse hooks offer useful telemetry but cannot
replace an isolated gateway, because other shell/network paths may bypass them.

### OpenAI Agents SDK integration

Tool input guardrails, tool approvals and function-tool wrappers integrate with
the agent application's execution loop, not with independent authorization.
Have the wrapper call the protected gateway, which revalidates identity, policy,
one-use action grant, idempotency and destination effect. Do not derive authority
solely from a resumed SDK tool-call approval. This repository already contains
offline approval and audit regression tests in
labs/openai_agents_sdk_integrity/.

### MCP server authentication

For remote Streamable HTTP, use the MCP SDK's OAuth resource-server support and
verify expected token issuer, tenant, audience, scope and caller. Local stdio
transport does not create that HTTP authentication boundary:
https://py.sdk.modelcontextprotocol.io/run/authorization/

## Current implemented surface

- agentproof.chain_anchor.seal_batch: witness takes **already authenticated
  and minimized** receipt dictionaries, assigns random 256-bit salts, sequential
  indices, creates domain-separated SHA-256 Merkle nodes, and signs the checkpoint
  with Ed25519.
- verify_batch: checks witness signature against a separately trusted public key,
  exact record count/order and root, including forged-header rejection.
- inclusion_proof / verify_inclusion: verify one exact receipt without sending
  an entire private batch to another party.
- verify_checkpoint_chain: verify two adjacent signed epochs and contiguous
  sequences. Signature alone does not establish the absence of historical gaps.
- contracts/AgentProofAnchor.sol: minimal EVM contract with per-publisher
  stream namespaces, monotone epochs, previous-on-chain-anchor matching and
  event emission. **Not deployed or compiler-tested yet.**

Offline checks:

    python -m pip install -e '.[chain]'
    python -m unittest discover -s tests -p 'test_chain_anchor.py' -v

Witness-only demonstration (ephemeral key; do not reuse for production):

    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from agentproof.chain_anchor import seal_batch, public_key_hex, verify_batch
    witness_private_key = Ed25519PrivateKey.generate()
    bundle = seal_batch([{"action":"synthetic-read","outcome":"verified"}],
                        witness_private_key, stream_id="demo",
                        epoch=1, first_sequence=1)
    assert verify_batch(bundle, public_key_hex(witness_private_key))

Store the complete bundle privately. Publishing only a salted Merkle root avoids
putting raw customer data on chain. Salts lower dictionary-attack risk but are
not encryption. Do not put private action identifiers in public stream IDs.

## EVM anchoring and two separate chains

The independent publisher calls AgentProofAnchor.anchor(streamIdHash, epoch,
signedCheckpoint.merkle_root, lastOnchainAnchor) on an EVM chain such as Base.
The first lastOnchainAnchor is zero. The contract emits its next anchor.

The *signed off-chain checkpoint's* previous_checkpoint_hash refers to the
previous signed checkpoint; it is **not** the contract's on-chain anchor.
An external verifier needs to check both histories, the trusted witness key,
the expected (chainId, contractAddress, publisher, streamIdHash), the finalized
transaction/event, the epoch, root and Merkle inclusion.

A blockchain proves inclusion in a **published commitment**, not that all real
AI actions were logged, not that an omitted request happened, and not that
the claimed external side effect actually occurred.

## Cases and remaining work

| Property | State |
| --- | --- |
| Altered receipt or forged signature rejected | Offline tests passed |
| Missing/reordered record rejected | Offline tests passed |
| Bad inclusion path/odd-leaf spoof rejected | Offline tests passed |
| Adjacent signed checkpoint sequences verified | Offline tests passed |
| Gateway shell/network bypass impossible | Unverified; requires isolated deployment |
| Missing action before witness ingestion detected | Unsolved; needs durable independent ingress ACK |
| External API side effect after timeout reconciled | Unsolved; needs destination-side idempotency |
| Ethereum/Base contract compiled, deployed and queried | Not yet performed |
| Signer rotation, L2 finality, availability and failover | Not implemented |

Next, implement **one** protected agent tool end to end using the repository's
existing PostgreSQL one-use transaction gate and independent effect observer.
Have the gateway submit intent to a durable external witness before performing
the side effect (fail closed on missing ACK). Reconcile ambiguous commits by
trusted readback, then anchor synthetic receipt batches on Base Sepolia, verify
the resulting chain event independently and attack the bypass paths.

ERC-8004 (https://eips.ethereum.org/EIPS/eip-8004) provides an agent
identity/reputation/validation ecosystem. Ethereum Attestation Service
(https://attest.org/) provides attestations. Interoperability may eventually
make sense. **Do not create a token until there is an economic necessity.**
