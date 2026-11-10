# PrecedentRegistry

An evolving technical standard and case-law registry Intelligent Contract on GenLayer. Rather than evaluating isolated claims globally, validators assess candidate rules against the path-dependent active canon using two isolated LLM consensus calls: (1) whether evidence explicitly supports the rule premise, and (2) whether the candidate relates to existing active rules as `INITIAL`, `ORTHOGONAL`, `NARROWS`, `CONTRADICTS`, or `DUPLICATES`. Accepted rules permanently modify the active canon, while parent retractions trigger deterministic BFS tree invalidation—cascading `RETRACTED` parents down to `ORPHANED_BY_PARENT` child carve-outs while preserving unaffected orthogonal rules as `ACTIVE`.

**Deployed StudioNet (Chain ID 61999):** [`0x6793beCe04293044cFa6feabb24401231E666602`](https://explorer-studio.genlayer.com/address/0x6793beCe04293044cFa6feabb24401231E666602)  
**Probe Contract:** [`0xe950C5Bf02D08142E9b290150001a515Cc808470`](https://explorer-studio.genlayer.com/address/0xe950C5Bf02D08142E9b290150001a515Cc808470)  
**Contract Source Commit:** [`5d15e81`](https://github.com/khezzed/PrecedentRegistry/commit/5d15e8173e5272e78fa5a4ca18dd90e415989d6f) | **Git Blob:** `76fe77ffcb28945afb0913979fb94ddd7f89043c` | **SHA-256:** `91bc3c12f4fa6a55892aee3e1f0f58b2e821cec1b68dee520f0068acbd738b71`  
**Manifest & Proof:** [`deploy/manifest.json`](deploy/manifest.json) (100% byte-for-byte on-chain equality verified)

### Finalized Live StudioNet Demo (`http-retry`)

| Step | Method | Description | Outcome | StudioNet Explorer Tx |
|---|---|---|---|---|
| **S1** | `open_domain` | Domain initialization (`http-retry`, 780s) | OPENED:http-retry | [`0x60b6910b...`](https://explorer-studio.genlayer.com/tx/0x60b6910bfee7577c37651d163d6e725b56f6e6f523ef70e21a52bde4856ceade) |
| **S2** | `propose_entry` | Initial root 5xx retry rule (`e1`) | ADMITTED:ENTRY_1 (INITIAL) | [`0xb7f85490...`](https://explorer-studio.genlayer.com/tx/0xb7f85490eeee8bb3e8d485b47c6471809bff1e45150a0db9dea48f74323830df) |
| **S3** | `propose_entry` | Path-dependence: conflicting root 503 rule (`e2`) | REJECTED:CONTRADICTS | [`0xa2978f06...`](https://explorer-studio.genlayer.com/tx/0xa2978f06193eae099b43037ea3742a85bf2eeaa886ffcf65df47588d98783f2f) |
| **S4** | `propose_entry` | Narrowing carve-out under Entry 1 (`e2`) | ADMITTED:ENTRY_2 (NARROWS) | [`0x14c44dab...`](https://explorer-studio.genlayer.com/tx/0x14c44dabfc3e07392b80d7719d6eac62bbb6dbe7ddb5034151917c51b037352d) |
| **S5** | `propose_entry` | Orthogonal 429 rate-limit rule (`e3`) | ADMITTED:ENTRY_3 (ORTHOGONAL) | [`0x08d092f9...`](https://explorer-studio.genlayer.com/tx/0x08d092f9c3542cac92714c0f076695c073ced9a2ead66bbc2c87dd0d0a55b686) |
| **X1** | `propose_entry` | [Expected Failure] Unrelated lemon tart recipe (`e5`) | REJECTED:PREMISE_UNSUPPORTED | [`0x41c20d12...`](https://explorer-studio.genlayer.com/tx/0x41c20d1274cb68aa0b3d9bd328c3eec5e0e2cff46dee37a2ff05e888bc8957fe) |
| **X2** | `propose_entry` | [Expected Failure] Duplicate proposal replay | UserError: REPLAY_SUBMISSION | [`0x9640768f...`](https://explorer-studio.genlayer.com/tx/0x9640768f075f38d0e57245a18184b79e15f7730ce6d940957c71f97e1754561f) |
| **X3** | `retract_entry` | [Expected Failure] Unauthorized retraction by Account C | UserError: UNAUTHORIZED_RETRACTION | [`0xde09ea14...`](https://explorer-studio.genlayer.com/tx/0xde09ea14711cfb6b1f9f37a6d166bb6fdffc4f991c87acd356dd4839dae088c6) |
| **X4** | `propose_entry` | [Expected Failure] Mutable unpinned `/main/` URL | UserError: INVALID_EVIDENCE_URL | [`0xff943de0...`](https://explorer-studio.genlayer.com/tx/0xff943de0fbfde3847f145979cc08abe76c2b1194e90343d946addbbd489d23d1) |
| **X5** | `freeze_epoch` | [Expected Failure] Premature epoch freeze before deadline | UserError: EPOCH_NOT_READY | [`0xf12c234e...`](https://explorer-studio.genlayer.com/tx/0xf12c234eea4e781d2ff43b16306e9cc85aaec38c3288e8387fba5b1705cced24) |
| **S6** | `retract_entry` | Author A retracts Entry 1 (`e4`), cascading to child | RETRACTED:ENTRY_1:ORPHANED_1 | [`0x6d4af5e3...`](https://explorer-studio.genlayer.com/tx/0x6d4af5e32b07998d00814bb64cdfe5789c2972520f56a5f65bb59545887a3ed0) |
| **X6** | `propose_entry` | [Expected Failure] Carve-out on orphaned Entry 2 | UserError: PARENT_NOT_ACTIVE | [`0xc369471b...`](https://explorer-studio.genlayer.com/tx/0xc369471b342a14aeb6bc487aed29835e4549e577df9daaa62f6c83541b62703e) |
| **S7** | `freeze_epoch` | Permissionless epoch freeze by Account C | FROZEN:EPOCH_1:DIGEST_6033794b... | [`0x0503d9d8...`](https://explorer-studio.genlayer.com/tx/0x0503d9d8ab852bd4a938dcf3e7e8247fa3d6c0f343bb87bbe3aab10d90788ebb) |
| **X7** | `freeze_epoch` | [Expected Failure] Double freeze attempt | UserError: DOMAIN_ALREADY_FROZEN | [`0x66669492...`](https://explorer-studio.genlayer.com/tx/0x66669492d15b28f5f2143fe146c666e7aba896a3808f68059f13fc027307f9d7) |

**Local Testing:** Run `pytest tests -v` (30 unit tests pass locally in ~0.5s).  
**Honest Scope:** Demonstrates path-dependent precedent evolution and deterministic tree invalidation over pinned UTF-8 policy/errata evidence; does not handle financial token/value escrow transfers.
