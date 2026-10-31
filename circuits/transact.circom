pragma circom 2.1.6;

include "poseidon.circom";
include "bitify.circom";
include "comparators.circom";

template Hash2() {
    signal input left;
    signal input right;
    signal output out;

    component hasher = Poseidon(2);
    hasher.inputs[0] <== left;
    hasher.inputs[1] <== right;
    out <== hasher.out;
}

template Commitment() {
    signal input value;
    signal input npk;
    signal input blinding;
    signal input token;
    signal output out;

    // ownerHash hides the note key. The chain sees this hash, not npk.
    component owner = Hash2();
    component left = Hash2();
    component root = Hash2();
    owner.left <== npk;
    owner.right <== blinding;
    left.left <== value;
    left.right <== token;
    root.left <== left.out;
    root.right <== owner.out;
    out <== root.out;
}

template Choose() {
    signal input whenZero;
    signal input whenOne;
    signal input bit;
    signal output out;

    bit * (bit - 1) === 0;
    out <== whenZero + bit * (whenOne - whenZero);
}

template MerkleLevel() {
    signal input node;
    signal input sibling;
    signal input index;
    signal output out;

    component left = Choose();
    component right = Choose();
    left.whenZero <== node;
    left.whenOne <== sibling;
    left.bit <== index;
    right.whenZero <== sibling;
    right.whenOne <== node;
    right.bit <== index;

    component hasher = Hash2();
    hasher.left <== left.out;
    hasher.right <== right.out;
    out <== hasher.out;
}

template Merkle(levels) {
    signal input leaf;
    signal input siblings[levels];
    signal input indices[levels];
    signal output root;

    component level[levels];
    signal nodes[levels + 1];
    nodes[0] <== leaf;

    for (var i = 0; i < levels; i++) {
        level[i] = MerkleLevel();
        level[i].node <== nodes[i];
        level[i].sibling <== siblings[i];
        level[i].index <== indices[i];
        nodes[i + 1] <== level[i].out;
    }

    root <== nodes[levels];
}

template Range128() {
    signal input in;
    component bits = Num2Bits(128);
    bits.in <== in;
}

/// Two notes in and two notes out. The notes may be two different tokens.
/// A disabled note contributes zero. Each public exit has its own fee.
/// The broadcaster tip is taken from the first token. The contract checks the fees.
template Transact(levels) {
    signal input merkleRoot;
    signal input nullifier0;
    signal input nullifier1;
    signal input commitment0;
    signal input commitment1;
    signal input publicAmount0;
    signal input publicAmount1;
    signal input recipient;
    signal input token0;
    signal input token1;
    signal input twoTokens;
    signal input relayFee;
    signal input protocolFee0;
    signal input protocolFee1;
    signal input relayRecipient;
    signal input externalHash;
    signal input ciphertextHash;

    // Real token ids. They stay off the public inputs when that bucket pays nothing out.
    signal input privateToken0;
    signal input privateToken1;

    signal input inValue[2];
    signal input inNpk[2];
    signal input inBlinding[2];
    signal input inToken[2];
    signal input inSpendingKey[2];
    signal input inSiblings[2][levels];
    signal input inIndices[2][levels];
    signal input inEnabled[2];

    signal input outValue[2];
    signal input outNpk[2];
    signal input outBlinding[2];
    signal input outToken[2];
    signal input outEnabled[2];

    twoTokens * (twoTokens - 1) === 0;
    component tokensDiffer = IsEqual();
    tokensDiffer.in[0] <== privateToken0;
    tokensDiffer.in[1] <== privateToken1;
    tokensDiffer.out * twoTokens === 0;
    privateToken1 * (1 - twoTokens) === 0;

    component bucket0Closed = IsZero();
    component bucket1Closed = IsZero();
    bucket0Closed.in <== publicAmount0 + protocolFee0 + relayFee;
    bucket1Closed.in <== publicAmount1 + protocolFee1;
    signal reveal0;
    signal reveal1;
    reveal0 <== 1 - bucket0Closed.out;
    reveal1 <== 1 - bucket1Closed.out;
    reveal1 * (1 - twoTokens) === 0;
    // A payout publishes its token. A private bucket publishes zero, which is not a second ETH exit.
    token0 === reveal0 * privateToken0;
    token1 === reveal1 * privateToken1;

    component publicRange0 = Range128();
    component publicRange1 = Range128();
    component relayRange = Range128();
    component feeRange0 = Range128();
    component feeRange1 = Range128();
    publicRange0.in <== publicAmount0;
    publicRange1.in <== publicAmount1;
    relayRange.in <== relayFee;
    feeRange0.in <== protocolFee0;
    feeRange1.in <== protocolFee1;

    signal recipientBound;
    signal relayRecipientBound;
    signal externalHashBound;
    signal ciphertextHashBound;
    recipientBound <== recipient * recipient;
    relayRecipientBound <== relayRecipient * relayRecipient;
    externalHashBound <== externalHash * externalHash;
    ciphertextHashBound <== ciphertextHash * ciphertextHash;

    component inRange[2];
    component inCommitment[2];
    component inNpkCheck[2];
    component inNullifier[2];
    component inMerkle[2];
    component inIs0[2];
    component inIs1[2];
    component inNpkZero[2];
    signal computedNullifier[2];
    signal inPart0[2];
    signal inPart1[2];
    signal inSingle[2];
    signal inMember[2];
    signal inMatch1[2];

    for (var i = 0; i < 2; i++) {
        inEnabled[i] * (inEnabled[i] - 1) === 0;
        inRange[i] = Range128();
        inRange[i].in <== inValue[i];
        inValue[i] * (1 - inEnabled[i]) === 0;
        inSpendingKey[i] * (1 - inEnabled[i]) === 0;
        inToken[i] * (1 - inEnabled[i]) === 0;
        inSingle[i] <== (inToken[i] - privateToken0) * inEnabled[i];
        inSingle[i] * (1 - twoTokens) === 0;
        inNpkZero[i] = IsZero();
        inNpkZero[i].in <== inNpk[i];
        inNpkZero[i].out * inEnabled[i] === 0;

        inIs0[i] = IsEqual();
        inIs0[i].in[0] <== inToken[i];
        inIs0[i].in[1] <== privateToken0;
        inIs1[i] = IsEqual();
        inIs1[i].in[0] <== inToken[i];
        inIs1[i].in[1] <== privateToken1;
        inMember[i] <== (inIs0[i].out + inIs1[i].out - 1) * inEnabled[i];
        inMember[i] * twoTokens === 0;

        inCommitment[i] = Commitment();
        inCommitment[i].value <== inValue[i];
        inCommitment[i].npk <== inNpk[i];
        inCommitment[i].blinding <== inBlinding[i];
        inCommitment[i].token <== inToken[i];

        inNpkCheck[i] = Hash2();
        inNpkCheck[i].left <== inSpendingKey[i];
        inNpkCheck[i].right <== 1;
        (inNpk[i] - inNpkCheck[i].out) * inEnabled[i] === 0;

        inNullifier[i] = Hash2();
        inNullifier[i].left <== inSpendingKey[i];
        inNullifier[i].right <== inCommitment[i].out;
        computedNullifier[i] <== inNullifier[i].out * inEnabled[i];

        inMerkle[i] = Merkle(levels);
        inMerkle[i].leaf <== inCommitment[i].out;
        for (var level = 0; level < levels; level++) {
            inMerkle[i].siblings[level] <== inSiblings[i][level];
            inMerkle[i].indices[level] <== inIndices[i][level];
        }
        (inMerkle[i].root - merkleRoot) * inEnabled[i] === 0;

        inPart0[i] <== inValue[i] * inIs0[i].out;
        inMatch1[i] <== inValue[i] * inIs1[i].out;
        inPart1[i] <== inMatch1[i] * twoTokens;
    }

    nullifier0 === computedNullifier[0];
    nullifier1 === computedNullifier[1];

    component outRange[2];
    component outCommitment[2];
    component outIs0[2];
    component outIs1[2];
    component outNpkZero[2];
    component outValueZero[2];
    signal computedCommitment[2];
    signal outPart0[2];
    signal outPart1[2];
    signal outSingle[2];
    signal outMember[2];
    signal outMatch1[2];

    for (var i = 0; i < 2; i++) {
        outEnabled[i] * (outEnabled[i] - 1) === 0;
        outRange[i] = Range128();
        outRange[i].in <== outValue[i];
        outValue[i] * (1 - outEnabled[i]) === 0;
        outToken[i] * (1 - outEnabled[i]) === 0;
        outSingle[i] <== (outToken[i] - privateToken0) * outEnabled[i];
        outSingle[i] * (1 - twoTokens) === 0;
        outNpkZero[i] = IsZero();
        outNpkZero[i].in <== outNpk[i];
        outNpkZero[i].out * outEnabled[i] === 0;
        outValueZero[i] = IsZero();
        outValueZero[i].in <== outValue[i];
        outValueZero[i].out * outEnabled[i] === 0;

        outIs0[i] = IsEqual();
        outIs0[i].in[0] <== outToken[i];
        outIs0[i].in[1] <== privateToken0;
        outIs1[i] = IsEqual();
        outIs1[i].in[0] <== outToken[i];
        outIs1[i].in[1] <== privateToken1;
        outMember[i] <== (outIs0[i].out + outIs1[i].out - 1) * outEnabled[i];
        outMember[i] * twoTokens === 0;

        outCommitment[i] = Commitment();
        outCommitment[i].value <== outValue[i];
        outCommitment[i].npk <== outNpk[i];
        outCommitment[i].blinding <== outBlinding[i];
        outCommitment[i].token <== outToken[i];
        computedCommitment[i] <== outCommitment[i].out * outEnabled[i];
        outPart0[i] <== outValue[i] * outIs0[i].out;
        outMatch1[i] <== outValue[i] * outIs1[i].out;
        outPart1[i] <== outMatch1[i] * twoTokens;
    }

    commitment0 === computedCommitment[0];
    commitment1 === computedCommitment[1];

    inPart0[0] + inPart0[1] === outPart0[0] + outPart0[1] + publicAmount0 + protocolFee0 + relayFee;
    inPart1[0] + inPart1[1] === outPart1[0] + outPart1[1] + publicAmount1 + protocolFee1;
}

component main {public [
    merkleRoot,
    nullifier0,
    nullifier1,
    commitment0,
    commitment1,
    publicAmount0,
    publicAmount1,
    recipient,
    token0,
    token1,
    twoTokens,
    relayFee,
    protocolFee0,
    protocolFee1,
    relayRecipient,
    externalHash,
    ciphertextHash
]} = Transact(16);
