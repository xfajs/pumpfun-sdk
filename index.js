require('dotenv');
const fs = require('fs');
const path = require('path');

const logFile = path.join(__dirname, 'logs.txt');
function logToFile(message) {
    const timestamp = new Date().toISOString();
    const logEntry = `[${timestamp}] ${message}\n`;
    fs.appendFileSync(logFile, logEntry, 'utf8');
}
const originalConsoleLog = console.log;
console.log = function (...args) {
    originalConsoleLog.apply(console, args);
    logToFile(args.join(' '));
};

const {
    Connection,
    PublicKey,
    Keypair,
    SystemProgram,
    Transaction,
    TransactionInstruction,
    ComputeBudgetProgram,
    LAMPORTS_PER_SOL,
    VersionedTransaction,
    TransactionMessage
} = require('@solana/web3.js');
const {
    getAssociatedTokenAddress,
    createAssociatedTokenAccountInstruction,
    TOKEN_PROGRAM_ID,
    TOKEN_2022_PROGRAM_ID,
    ASSOCIATED_TOKEN_PROGRAM_ID,
} = require('@solana/spl-token');

const axios = require('axios');
const bs58 = require('bs58');
const crypto = require('crypto');
const bip39 = require('bip39');
const { derivePath } = require('ed25519-hd-key');
const config = require('./config.json');

const RPC_URL = process.env.RPC_URL;
if (!RPC_URL) throw new Error('Missing RPC_URL in env');

const connection = new Connection(RPC_URL, 'confirmed');

const PUMP_SWAP_PROGRAM_ID = new PublicKey('pAMMBay6oceH9fJKBRHGP5D4bD4sWpmSwMn52FMfXEA');
const PUMP_SWAP_GLOBAL_CONFIG = PublicKey.findProgramAddressSync(
    [Buffer.from('global')],
    PUMP_SWAP_PROGRAM_ID
)[0];
const PUMP_PROGRAM_ID = new PublicKey('6EF8rrecthR5Dkzon8Nwu78hRvfCKubJ14M5uBEwF6P');
const PUMP_FEE_PROGRAM_ID = new PublicKey('pfeeUxB6jkeY1Hxd7CsFCAjcbHA9rWtchMGdZ6VojVZ');
const PUMP_FEE_RECIPIENT = new PublicKey('CebN5WGQ4jvEPvsVU4EoHEpgzq1VV7AbicfhtW4xC9iM');
const PUMP_FEE_ACCOUNT = new PublicKey('568d5EvaukJrQjGGcVdnvtp69GLZmgsSMHCErvdZ8Vpj');
const MPL_TOKEN_METADATA_PROGRAM_ID = new PublicKey('metaqbxxUerdq28cj1RbAWkYQm3ybzjb6a8bt518x1s');
const SYSVAR_RENT = new PublicKey('SysvarRent111111111111111111111111111111111');

const PUMP_GLOBAL = PublicKey.findProgramAddressSync([Buffer.from('global')], PUMP_PROGRAM_ID)[0];
const PUMP_EVENT_AUTHORITY = PublicKey.findProgramAddressSync([Buffer.from('__event_authority')], PUMP_PROGRAM_ID)[0];
const PUMP_GLOBAL_VOLUME_ACCUMULATOR = PublicKey.findProgramAddressSync(
    [Buffer.from('global_volume_accumulator')],
    PUMP_PROGRAM_ID
)[0];
const PUMP_FEE_CONFIG = PublicKey.findProgramAddressSync(
    [Buffer.from('fee_config'), PUMP_PROGRAM_ID.toBuffer()],
    PUMP_FEE_PROGRAM_ID
)[0];

const CLAIM_FEE_BPS = 2500;
const PRIORITY_FEE_SOL = 0.0001;


function computeUnitPriceMicrolamports(unitLimit) {
    const feeLamports = Math.floor(PRIORITY_FEE_SOL * LAMPORTS_PER_SOL);
    return Math.max(0, Math.floor((feeLamports * 1_000_000) / unitLimit));
}

function keypairFromPrivateKey(pk) {
    if (typeof pk === 'string') {
        const trimmed = pk.trim();
        if (trimmed.startsWith('[')) {
            pk = JSON.parse(trimmed);
        } else {
            pk = bs58.decode(trimmed);
        }
    }
    if (Array.isArray(pk)) pk = Uint8Array.from(pk);
    if (!(pk instanceof Uint8Array)) {
        throw new Error('privateKey must be Uint8Array, array, or JSON string array');
    }
    return Keypair.fromSecretKey(pk);
}

async function tokenProgramForMint(mintPk) {
    const info = await connection.getAccountInfo(mintPk);
    if (!info) throw new Error('Mint not found');
    return info.owner.equals(TOKEN_2022_PROGRAM_ID) ? TOKEN_2022_PROGRAM_ID : TOKEN_PROGRAM_ID;
}

function anchorDisc(name) {
    return crypto.createHash('sha256').update(`global:${name}`).digest().subarray(0, 8);
}

function bondingCurvePda(mintPk) {
    return PublicKey.findProgramAddressSync([Buffer.from('bonding-curve'), mintPk.toBuffer()], PUMP_PROGRAM_ID)[0];
}

function mintAuthorityPda() {
    return PublicKey.findProgramAddressSync([Buffer.from('mint-authority')], PUMP_PROGRAM_ID)[0];
}

function metadataPda(mintPk) {
    return PublicKey.findProgramAddressSync(
        [Buffer.from('metadata'), MPL_TOKEN_METADATA_PROGRAM_ID.toBuffer(), mintPk.toBuffer()],
        MPL_TOKEN_METADATA_PROGRAM_ID
    )[0];
}

function creatorVaultPda(creator) {
    return PublicKey.findProgramAddressSync([Buffer.from('creator-vault'), creator.toBuffer()], PUMP_PROGRAM_ID)[0];
}

function userVolumeAccumulatorPda(user) {
    return PublicKey.findProgramAddressSync([Buffer.from('user_volume_accumulator'), user.toBuffer()], PUMP_PROGRAM_ID)[0];
}

async function getCreatorVaultBalance(creatorPubkey) {
    const creator = typeof creatorPubkey === 'string' ? new PublicKey(creatorPubkey) : creatorPubkey;
    const vault = creatorVaultPda(creator);
    const balance = await connection.getBalance(vault);
    return balance / LAMPORTS_PER_SOL;
}

async function getBondingCurveState(mintPk, tokenProgramId) {
    const bondingCurve = bondingCurvePda(mintPk);
    const associatedBondingCurve = await getAssociatedTokenAddress(
        mintPk,
        bondingCurve,
        true,
        tokenProgramId,
        ASSOCIATED_TOKEN_PROGRAM_ID
    );

    const info = await connection.getAccountInfo(bondingCurve);
    if (!info) return null;

    const d = info.data;
    return {
        bondingCurve,
        associatedBondingCurve,
        virtualTokenReserves: d.readBigUInt64LE(8),
        virtualSolReserves: d.readBigUInt64LE(16),
        complete: d[48] === 1,
        creator: new PublicKey(d.slice(49, 81)),
    };
}

function calculatePumpFee(tx, userPubkey, lamportsIn) {
  const lamports = BigInt(lamportsIn);
  const pumpFeeBig = (lamports * 10n) / 100n;
  const tradeLamportsBig = lamports - pumpFeeBig;

  if (tradeLamportsBig <= 0n) {
    throw new Error('Pump fee exceeds input amount');
  }

  const pumpFee = Number(pumpFeeBig);
  const tradeLamports = Number(tradeLamportsBig);

  if (pumpFee > 0) {
    tx.add(
      SystemProgram.transfer({
        fromPubkey: userPubkey,
        toPubkey: PUMP_FEE_ACCOUNT,
        lamports: pumpFee,
      })
    );
  }
  const keepLamports = tradeLamports;

  return {
    keepLamports,
    pumpFee,
    tradeLamports,
  };
}



async function sendTx(tx, signers) {
    const { blockhash, lastValidBlockHeight } = await connection.getLatestBlockhash('confirmed');
    if (tx instanceof Transaction) {
        tx.feePayer = signers[0].publicKey;
        tx.recentBlockhash = blockhash;
        tx.sign(...signers);
        const rawTx = tx.serialize();
        const sig = await connection.sendRawTransaction(rawTx, {
            skipPreflight: false,
            maxRetries: 5,
        });
        await connection.confirmTransaction(
            { signature: sig, blockhash, lastValidBlockHeight },
            'confirmed'
        );
        return sig;
    }

    else if (tx instanceof VersionedTransaction) {
        tx.message.recentBlockhash = blockhash;
        tx.sign(signers);

        const rawTx = tx.serialize();
        const sig = await connection.sendRawTransaction(rawTx, {
            skipPreflight: false,
            maxRetries: 5,
        });
        await connection.confirmTransaction(
            { signature: sig, blockhash, lastValidBlockHeight },
            'confirmed'
        );
        return sig;
    }

    else {
        throw new Error('Unsupported transaction type: must be Transaction or VersionedTransaction');
    }
}

async function buyToken({ privateKey, mint, sol, slippageBps = 500 }) {
    const user = keypairFromPrivateKey(privateKey);
    const mintPk = new PublicKey(mint);
    const lamportsIn = Math.floor(sol * LAMPORTS_PER_SOL);
    const tokenProgramId = await tokenProgramForMint(mintPk);

    const balance = await connection.getBalance(user.publicKey);
    const minSol = config.emptyBalanceNotifyThresholdSol;
    if (balance < minSol * LAMPORTS_PER_SOL) {
        throw new Error(`Wallet balance too low (min ${minSol} SOL)`);
    }

    const curve = await getBondingCurveState(mintPk, tokenProgramId);
    if (!curve) throw new Error('Bonding curve not found');

    // ─── PATH 1: PRE-BONDED (Pump.fun native bonding curve) ─────────────────
    if (!curve.complete) {
        const { blockhash, lastValidBlockHeight } = await connection.getLatestBlockhash('confirmed');
        const tx = new Transaction();

        const userAta = await getAssociatedTokenAddress(
            mintPk, user.publicKey, false, tokenProgramId, ASSOCIATED_TOKEN_PROGRAM_ID
        );
        const bcAta = await getAssociatedTokenAddress(
            mintPk, curve.bondingCurve, true, tokenProgramId, ASSOCIATED_TOKEN_PROGRAM_ID
        );

        if (!(await connection.getAccountInfo(userAta))) {
            tx.add(
                createAssociatedTokenAccountInstruction(
                    user.publicKey, userAta, user.publicKey, mintPk, tokenProgramId, ASSOCIATED_TOKEN_PROGRAM_ID
                )
            );
        }

        if (!(await connection.getAccountInfo(bcAta))) {
            tx.add(
                createAssociatedTokenAccountInstruction(
                    user.publicKey, bcAta, curve.bondingCurve, mintPk, tokenProgramId, ASSOCIATED_TOKEN_PROGRAM_ID
                )
            );
        }

        const { tradeLamports } = calculatePumpFee(tx, user.publicKey, lamportsIn);
        const tradeLamportsBig = BigInt(tradeLamports);

        const newSol = curve.virtualSolReserves + tradeLamportsBig;
        const newToken = (curve.virtualSolReserves * curve.virtualTokenReserves) / newSol;
        const tokensOut = curve.virtualTokenReserves - newToken;
        const maxSolCost = tradeLamportsBig + (tradeLamportsBig * BigInt(slippageBps)) / 10_000n;

        const data = Buffer.concat([anchorDisc('buy'), Buffer.alloc(8), Buffer.alloc(8)]);
        data.writeBigUInt64LE(tokensOut, 8);
        data.writeBigUInt64LE(maxSolCost, 16);

        tx.add(
            new TransactionInstruction({
                programId: PUMP_PROGRAM_ID,
                keys: [
                    { pubkey: PUMP_GLOBAL, isSigner: false, isWritable: false },
                    { pubkey: PUMP_FEE_RECIPIENT, isSigner: false, isWritable: true },
                    { pubkey: mintPk, isSigner: false, isWritable: false },
                    { pubkey: curve.bondingCurve, isSigner: false, isWritable: true },
                    { pubkey: bcAta, isSigner: false, isWritable: true },
                    { pubkey: userAta, isSigner: false, isWritable: true },
                    { pubkey: user.publicKey, isSigner: true, isWritable: true },
                    { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
                    { pubkey: tokenProgramId, isSigner: false, isWritable: false },
                    { pubkey: creatorVaultPda(curve.creator), isSigner: false, isWritable: true },
                    { pubkey: PUMP_EVENT_AUTHORITY, isSigner: false, isWritable: false },
                    { pubkey: PUMP_PROGRAM_ID, isSigner: false, isWritable: false },
                    { pubkey: PUMP_GLOBAL_VOLUME_ACCUMULATOR, isSigner: false, isWritable: false },
                    { pubkey: userVolumeAccumulatorPda(user.publicKey), isSigner: false, isWritable: true },
                    { pubkey: PUMP_FEE_CONFIG, isSigner: false, isWritable: false },
                    { pubkey: PUMP_FEE_PROGRAM_ID, isSigner: false, isWritable: false },
                ],
                data
            })
        );

        tx.feePayer = user.publicKey;
        tx.recentBlockhash = blockhash;
        tx.sign(user);

        const sig = await connection.sendRawTransaction(tx.serialize(), {
            skipPreflight: false,
            maxRetries: 5,
        });

        await connection.confirmTransaction(
            { signature: sig, blockhash, lastValidBlockHeight },
            'confirmed'
        );

        return { signature: sig, tradeLamports };
    }

    else {
        const { blockhash, lastValidBlockHeight } = await connection.getLatestBlockhash('confirmed');
        const instructionCollector = new Transaction();

        const { tradeLamports } = calculatePumpFee(instructionCollector, user.publicKey, lamportsIn);

        const inputMint = 'So11111111111111111111111111111111111111112';
        const outputMint = mint;

        const quoteUrl = `https://public.jupiterapi.com/quote?inputMint=${inputMint}&outputMint=${outputMint}&amount=${tradeLamports}&slippageBps=${slippageBps}&onlyDirectRoutes=false`;

        let quoteResponse;
        try {
            const quoteRes = await axios.get(quoteUrl);
            quoteResponse = quoteRes.data;
        } catch (err) {
            throw new Error(`Jupiter quote failed: ${err.response?.status || ''} - ${err.response?.data?.error || err.message}`);
        }

        if (!quoteResponse || !quoteResponse.outAmount) {
            throw new Error('Invalid quote from Jupiter');
        }

        const instructionsUrl = 'https://public.jupiterapi.com/swap-instructions';
        const body = {
            quoteResponse,
            userPublicKey: user.publicKey.toBase58(),
            wrapAndUnwrapSol: true,
            computeUnitPriceMicroLamports: computeUnitPriceMicrolamports(600_000),
            useSharedAccounts: true,
        };

        let swapInstructionsData;
        try {
            const res = await axios.post(instructionsUrl, body, {
                headers: { 'Content-Type': 'application/json' }
            });
            swapInstructionsData = res.data;
        } catch (err) {
            throw new Error(`Jupiter swap-instructions failed: ${err.response?.status || ''} - ${err.response?.data?.error || err.message}`);
        }

        const jupiterInstructions = [];

        if (swapInstructionsData.setupInstructions) {
            swapInstructionsData.setupInstructions.forEach(instr => {
                jupiterInstructions.push(new TransactionInstruction({
                    programId: new PublicKey(instr.programId),
                    keys: instr.accounts.map(a => ({
                        pubkey: new PublicKey(a.pubkey),
                        isSigner: a.isSigner,
                        isWritable: a.isWritable
                    })),
                    data: Buffer.from(instr.data, 'base64')
                }));
            });
        }

        if (swapInstructionsData.swapInstruction) {
            const instr = swapInstructionsData.swapInstruction;
            jupiterInstructions.push(new TransactionInstruction({
                programId: new PublicKey(instr.programId),
                keys: instr.accounts.map(a => ({
                    pubkey: new PublicKey(a.pubkey),
                    isSigner: a.isSigner,
                    isWritable: a.isWritable
                })),
                data: Buffer.from(instr.data, 'base64')
            }));
        }

        if (swapInstructionsData.cleanupInstruction) {
            const instr = swapInstructionsData.cleanupInstruction;
            jupiterInstructions.push(new TransactionInstruction({
                programId: new PublicKey(instr.programId),
                keys: instr.accounts.map(a => ({
                    pubkey: new PublicKey(a.pubkey),
                    isSigner: a.isSigner,
                    isWritable: a.isWritable
                })),
                data: Buffer.from(instr.data, 'base64')
            }));
        }

        instructionCollector.add(...jupiterInstructions);

        let lookupTables = [];
        if (swapInstructionsData.addressLookupTableAccounts) {
            lookupTables = swapInstructionsData.addressLookupTableAccounts.map(alt => ({
                key: new PublicKey(alt.key),
                writableIndexes: alt.writableIndexes || [],
                readonlyIndexes: alt.readonlyIndexes || []
            }));
        }

        const messageV0 = new TransactionMessage({
            payerKey: user.publicKey,
            recentBlockhash: blockhash,
            instructions: instructionCollector.instructions
        }).compileToV0Message(lookupTables);

        const versionedTx = new VersionedTransaction(messageV0);
        versionedTx.sign([user]);

        const sig = await sendTx(versionedTx, [user]);

        return { signature: sig, tradeLamports };
    }
}



async function claimCreatorFees({ privateKey, feeBps = CLAIM_FEE_BPS }) {
    const creator = keypairFromPrivateKey(privateKey);
    const creatorVault = creatorVaultPda(creator.publicKey);
    const beforeVault = (await connection.getAccountInfo(creatorVault))?.lamports ?? 0;

    const claimData = anchorDisc('collect_creator_fee');
    const claimKeys = [
        { pubkey: creator.publicKey, isSigner: true, isWritable: true },
        { pubkey: creatorVault, isSigner: false, isWritable: true },
        { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
        { pubkey: PUMP_EVENT_AUTHORITY, isSigner: false, isWritable: false },
        { pubkey: PUMP_PROGRAM_ID, isSigner: false, isWritable: false },
    ];

    const claimTx = new Transaction().add(
        ComputeBudgetProgram.setComputeUnitLimit({ units: 200_000 }),
        ComputeBudgetProgram.setComputeUnitPrice({ microLamports: computeUnitPriceMicrolamports(200_000) }),
        new TransactionInstruction({
            programId: PUMP_PROGRAM_ID,
            keys: claimKeys,
            data: claimData,
        })
    );

    const claimSig = await sendTx(claimTx, [creator]);
    const afterVault = (await connection.getAccountInfo(creatorVault))?.lamports ?? 0;
    const claimedLamports = Math.max(0, beforeVault - afterVault);

    let feeSig = null;
    let feeLamports = 0;
    if (claimedLamports > 0 && feeBps > 0) {
        feeLamports = Math.floor((claimedLamports * feeBps) / 10_000);
        if (feeLamports > 0) {
            const feeTx = new Transaction().add(
                ComputeBudgetProgram.setComputeUnitLimit({ units: 100_000 }),
                ComputeBudgetProgram.setComputeUnitPrice({ microLamports: computeUnitPriceMicrolamports(100_000) }),
                SystemProgram.transfer({
                    fromPubkey: creator.publicKey,
                    toPubkey: PUMP_FEE_ACCOUNT,
                    lamports: feeLamports,
                })
            );
            feeSig = await sendTx(feeTx, [creator]);
        }
    }

    return { claimSig, claimedLamports, feeSig, feeLamports };
}

function deriveWallet(index, masterSeed) {
    const seed = bip39.mnemonicToSeedSync(masterSeed || '');
    const path = `m/44'/501'/${index}'/0'`;
    const derived = derivePath(path, seed.toString('hex'));
    const kp = Keypair.fromSeed(derived.key);
    return { publicKey: kp.publicKey.toBase58(), privateKey: bs58.encode(kp.secretKey), index };
}

async function getWalletBalance(pubkey) {
    const balance = await connection.getBalance(new PublicKey(pubkey));
    return balance / LAMPORTS_PER_SOL;
}

async function preflightCheck(walletPubkey, minSol) {
    try {
        await connection.getLatestBlockhash('finalized');
    } catch (e) {
        throw new Error(`RPC unavailable: ${e.message}`);
    }
    let balLamports = 0;
    try {
        balLamports = await connection.getBalance(new PublicKey(walletPubkey));
    } catch (e) {
        throw new Error(`Balance check failed: ${e.message}`);
    }
    const balSol = balLamports / LAMPORTS_PER_SOL;
    if (balSol < minSol) throw new Error(`Insufficient SOL: ${balSol.toFixed(4)} / ${minSol}`);
    return { balSol };
}

async function burnTokens({ privateKey, mint }) {
    const signer = keypairFromPrivateKey(privateKey);
    const mintPk = new PublicKey(mint);
    const tokenProgramId = await tokenProgramForMint(mintPk);
    const userAta = await getAssociatedTokenAddress(mintPk, signer.publicKey, false, tokenProgramId, ASSOCIATED_TOKEN_PROGRAM_ID);
    const balance = await connection.getTokenAccountBalance(userAta).catch(() => null);
    const decimals = balance?.value?.decimals ?? 6;
    const amount = balance?.value?.amount ? BigInt(balance.value.amount) : 0n;
    if (amount === 0n) return { sig: null, amount: 0n, decimals };

    const { createBurnInstruction } = require('@solana/spl-token');
    const burnIx = createBurnInstruction(userAta, mintPk, signer.publicKey, amount, [], tokenProgramId);

    const tx = new Transaction().add(
        ComputeBudgetProgram.setComputeUnitLimit({ units: 100_000 }),
        ComputeBudgetProgram.setComputeUnitPrice({ microLamports: computeUnitPriceMicrolamports(100_000) }),
        burnIx
    );

    const sig = await sendTx(tx, [signer]);
    return { sig, amount, decimals };
}

async function deployToken({
    privateKey,
    name,
    symbol,
    metadataUri,
    initialBuySol = 0,
    simulate = false,
    mintKeypair = null,
} = {}) {
    const creator = keypairFromPrivateKey(privateKey);

    if (!mintKeypair) {
        throw new Error('mintKeypair required - no vanity generation available');
    }
    const mint = mintKeypair;

    if (!name || name.length > 32) throw new Error('Name must be 1-32 characters');
    if (!symbol || symbol.length > 10) throw new Error('Symbol must be 1-10 characters');
    if (!metadataUri) throw new Error('Metadata URI required');

    const bondingCurve = bondingCurvePda(mint.publicKey);
    const associatedBondingCurve = await getAssociatedTokenAddress(
        mint.publicKey,
        bondingCurve,
        true,
        TOKEN_PROGRAM_ID,
        ASSOCIATED_TOKEN_PROGRAM_ID
    );
    const metadata = metadataPda(mint.publicKey);
    const mintAuthority = mintAuthorityPda();
    const creatorVault = creatorVaultPda(creator.publicKey);
    const userVolumeAccumulator = userVolumeAccumulatorPda(creator.publicKey);

    const nameBytes = Buffer.from(name, 'utf8');
    const symbolBytes = Buffer.from(symbol, 'utf8');
    const uriBytes = Buffer.from(metadataUri, 'utf8');

    const dataLen = 8
        + 4 + nameBytes.length
        + 4 + symbolBytes.length
        + 4 + uriBytes.length
        + 32;

    const data = Buffer.alloc(dataLen);
    let offset = 0;

    anchorDisc('create').copy(data, offset);
    offset += 8;

    data.writeUInt32LE(nameBytes.length, offset);
    offset += 4;
    nameBytes.copy(data, offset);
    offset += nameBytes.length;

    data.writeUInt32LE(symbolBytes.length, offset);
    offset += 4;
    symbolBytes.copy(data, offset);
    offset += symbolBytes.length;

    data.writeUInt32LE(uriBytes.length, offset);
    offset += 4;
    uriBytes.copy(data, offset);
    offset += uriBytes.length;

    creator.publicKey.toBuffer().copy(data, offset);
    offset += 32;

    const createKeys = [
        { pubkey: mint.publicKey, isSigner: true, isWritable: true },
        { pubkey: mintAuthority, isSigner: false, isWritable: false },
        { pubkey: bondingCurve, isSigner: false, isWritable: true },
        { pubkey: associatedBondingCurve, isSigner: false, isWritable: true },
        { pubkey: PUMP_GLOBAL, isSigner: false, isWritable: false },
        { pubkey: MPL_TOKEN_METADATA_PROGRAM_ID, isSigner: false, isWritable: false },
        { pubkey: metadata, isSigner: false, isWritable: true },
        { pubkey: creator.publicKey, isSigner: true, isWritable: true },
        { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
        { pubkey: TOKEN_PROGRAM_ID, isSigner: false, isWritable: false },
        { pubkey: ASSOCIATED_TOKEN_PROGRAM_ID, isSigner: false, isWritable: false },
        { pubkey: SYSVAR_RENT, isSigner: false, isWritable: false },
        { pubkey: PUMP_EVENT_AUTHORITY, isSigner: false, isWritable: false },
        { pubkey: PUMP_PROGRAM_ID, isSigner: false, isWritable: false },
        { pubkey: creatorVault, isSigner: false, isWritable: true },
        { pubkey: PUMP_GLOBAL_VOLUME_ACCUMULATOR, isSigner: false, isWritable: true },
        { pubkey: userVolumeAccumulator, isSigner: false, isWritable: true },
    ];

    const tx = new Transaction().add(
        ComputeBudgetProgram.setComputeUnitLimit({ units: 400_000 }),
        ComputeBudgetProgram.setComputeUnitPrice({ microLamports: computeUnitPriceMicrolamports(400_000) }),
        new TransactionInstruction({
            programId: PUMP_PROGRAM_ID,
            keys: createKeys,
            data,
        })
    );

    if (initialBuySol > 0) {
        const userAta = await getAssociatedTokenAddress(
            mint.publicKey,
            creator.publicKey,
            false,
            TOKEN_PROGRAM_ID,
            ASSOCIATED_TOKEN_PROGRAM_ID
        );

        // Create ATA for user
        tx.add(
            createAssociatedTokenAccountInstruction(
                creator.publicKey,
                userAta,
                creator.publicKey,
                mint.publicKey,
                TOKEN_PROGRAM_ID,
                ASSOCIATED_TOKEN_PROGRAM_ID
            )
        );

        const INITIAL_VIRTUAL_TOKEN = 1_073_000_000_000_000n;
        const INITIAL_VIRTUAL_SOL = 30_000_000_000n;

        const lamportsIn = Math.floor(initialBuySol * LAMPORTS_PER_SOL);
        const tradeLamportsBig = BigInt(lamportsIn);

        const newSol = INITIAL_VIRTUAL_SOL + tradeLamportsBig;
        const newToken = (INITIAL_VIRTUAL_SOL * INITIAL_VIRTUAL_TOKEN) / newSol;
        const tokensOut = INITIAL_VIRTUAL_TOKEN - newToken;
        const maxSolCost = tradeLamportsBig + (tradeLamportsBig * 1000n) / 10_000n;

        const buyData = Buffer.concat([anchorDisc('buy'), Buffer.alloc(8), Buffer.alloc(8)]);
        buyData.writeBigUInt64LE(tokensOut, 8);
        buyData.writeBigUInt64LE(maxSolCost, 16);

        const buyKeys = [
            { pubkey: PUMP_GLOBAL, isSigner: false, isWritable: false },
            { pubkey: PUMP_FEE_RECIPIENT, isSigner: false, isWritable: true },
            { pubkey: mint.publicKey, isSigner: false, isWritable: false },
            { pubkey: bondingCurve, isSigner: false, isWritable: true },
            { pubkey: associatedBondingCurve, isSigner: false, isWritable: true },
            { pubkey: userAta, isSigner: false, isWritable: true },
            { pubkey: creator.publicKey, isSigner: true, isWritable: true },
            { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
            { pubkey: TOKEN_PROGRAM_ID, isSigner: false, isWritable: false },
            { pubkey: creatorVault, isSigner: false, isWritable: true },
            { pubkey: PUMP_EVENT_AUTHORITY, isSigner: false, isWritable: false },
            { pubkey: PUMP_PROGRAM_ID, isSigner: false, isWritable: false },
            { pubkey: PUMP_GLOBAL_VOLUME_ACCUMULATOR, isSigner: false, isWritable: false },
            { pubkey: userVolumeAccumulator, isSigner: false, isWritable: true },
            { pubkey: PUMP_FEE_CONFIG, isSigner: false, isWritable: false },
            { pubkey: PUMP_FEE_PROGRAM_ID, isSigner: false, isWritable: false },
        ];

        tx.add(new TransactionInstruction({ programId: PUMP_PROGRAM_ID, keys: buyKeys, data: buyData }));
    }

    tx.feePayer = creator.publicKey;
    const { blockhash } = await connection.getLatestBlockhash('processed');
    tx.recentBlockhash = blockhash;
    tx.sign(creator, mint);

    if (simulate) {
        const sim = await connection.simulateTransaction(tx, {
            sigVerify: true,
            replaceRecentBlockhash: true,
            commitment: 'processed',
        });
        if (sim.value.err) {
            const err = new Error(`Simulation failed: ${JSON.stringify(sim.value.err)}`);
            err.logs = sim.value.logs || [];
            throw err;
        }
        return {
            simulated: true,
            signature: null,
            mint: mint.publicKey.toBase58(),
            logs: sim.value.logs || [],
        };
    }

    const sig = await connection.sendRawTransaction(tx.serialize(), {
        skipPreflight: false,
        maxRetries: 5,
        preflightCommitment: 'processed',
    });
    await connection.confirmTransaction(sig, 'confirmed');

    return {
        signature: sig,
        mint: mint.publicKey.toBase58(),
        bondingCurve: bondingCurve.toBase58(),
    };
}

module.exports = {
    connection,
    keypairFromPrivateKey,
    tokenProgramForMint,
    calculatePumpFee: calculatePumpFee,
    sendTx,
    buyToken,
    claimCreatorFees,
    deployToken,
    deriveWallet,
    getWalletBalance,
    preflightCheck,
    burnTokens,
    getCreatorVaultBalance,
};
