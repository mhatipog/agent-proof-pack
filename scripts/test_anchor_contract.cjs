'use strict';
// Synthetic EVM test with no external chain, RPC key or funded wallet.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const ganache = require('ganache');
const solc = require('solc');
const { ethers } = require('ethers');

async function main() {
  const source = fs.readFileSync('contracts/AgentProofAnchor.sol', 'utf8');
  const input = { language: 'Solidity', sources: {'AgentProofAnchor.sol': {content: source}},
    settings: {outputSelection: {'*': {'*': ['abi', 'evm.bytecode.object']}}} };
  const output = JSON.parse(solc.compile(JSON.stringify(input)));
  const errors = (output.errors || []).filter(e => e.severity === 'error');
  assert.deepEqual(errors, [], 'Solidity compilation errors');
  const contractInfo = output.contracts['AgentProofAnchor.sol'].AgentProofAnchor;
  const provider = new ethers.BrowserProvider(ganache.provider({logging: {quiet: true}}));
  const publisher1 = await provider.getSigner(0);
  const publisher2 = await provider.getSigner(1);
  const contract = await new ethers.ContractFactory(contractInfo.abi,
    '0x' + contractInfo.evm.bytecode.object, publisher1).deploy();
  await contract.waitForDeployment();
  const stream = ethers.id('synthetic-stream');
  const otherStream = ethers.id('second-stream');
  const rootA = '0x' + 'aa'.repeat(32);
  const rootB = '0x' + 'bb'.repeat(32);
  const namespace = (address, name) => ethers.keccak256(
    ethers.AbiCoder.defaultAbiCoder().encode(['address', 'bytes32'], [address, name]));
  const key1 = namespace(await publisher1.getAddress(), stream);
  const key2 = namespace(await publisher2.getAddress(), stream);

  await assert.rejects(contract.anchor.staticCall(stream, 1, ethers.ZeroHash, ethers.ZeroHash),
    'reject empty root');
  const receipt = await (await contract.anchor(stream, 1, rootA, ethers.ZeroHash)).wait();
  assert.ok(receipt.logs.some(log => {
    try { const parsed = contract.interface.parseLog(log);
      return parsed && parsed.name === 'CheckpointAnchored' && parsed.args.root === rootA;
    } catch { return false; }
  }), 'emit public root event');
  const first = await contract.heads(key1);
  assert.equal(first.epoch, 1n);
  assert.notEqual(first.anchor, ethers.ZeroHash);

  await assert.rejects(contract.anchor.staticCall(stream, 1, rootA, first.anchor),
    'replay rejected');
  await assert.rejects(contract.anchor.staticCall(stream, 2, rootB, ethers.ZeroHash),
    'incorrect predecessor rejected');
  await (await contract.anchor(stream, 2, rootB, first.anchor)).wait();
  const second = await contract.heads(key1);
  assert.equal(second.epoch, 2n);
  assert.notEqual(second.anchor, first.anchor);

  // Publisher 2 can use the same name but not overwrite publisher 1's stream.
  const alternate = contract.connect(publisher2);
  await (await alternate.anchor(stream, 1, rootB, ethers.ZeroHash)).wait();
  assert.equal((await contract.heads(key2)).epoch, 1n);
  assert.equal((await contract.heads(key1)).epoch, 2n);
  // Different stream from publisher 1 starts with epoch 1 independently.
  await (await contract.anchor(otherStream, 1, rootA, ethers.ZeroHash)).wait();
  assert.equal((await contract.heads(namespace(await publisher1.getAddress(), otherStream))).epoch, 1n);
  console.log('PASS: deployed to isolated EVM, event, zero root, replay, predecessor, publisher and stream isolation');
}
main().catch(err => { console.error(err); process.exitCode = 1; });
