const crypto = require('crypto')
const secp256k1 = require('secp256k1')
const base58Check = require('base58check')

let receiverPrivKey
do {
  receiverPrivKey = crypto.randomBytes(32)
} while (!secp256k1.privateKeyVerify(receiverPrivKey))
const receiverPubKey = secp256k1.publicKeyCreate(receiverPrivKey)
const receiverPubKeyHash = crypto.createHmac('ripemd160', crypto.createHmac('sha256', receiverPubKey).digest()).digest()

let refundPrivKey
do {
  refundPrivKey = crypto.randomBytes(32)
} while (!secp256k1.privateKeyVerify(refundPrivKey))
const refundPubKey = secp256k1.publicKeyCreate(refundPrivKey)
const refundPubKeyHash = crypto.createHmac('ripemd160', crypto.createHmac('sha256', refundPubKey).digest()).digest()

const preimage = crypto.randomBytes(32)
const digest = crypto.createHmac('sha256', preimage).digest()
const LOCKTIME = 30 * 86400; // 30 days

const address = generateBIP199Address(receiverPubKeyHash, refundPubKeyHash, LOCKTIME)
console.log("Preimage: ", preimage.toString('hex'))
console.log("Hash: ", digest.toString('hex'))
console.log("Address: ", address)

function generateBIP199Address(receiverPubKeyHash, refundPubKeyHash, locktime) {
  const locktimeBuffer = numberToBuffer(locktime)

  // OP_IF
  //     OP_SHA256 <digest> OP_EQUALVERIFY OP_DUP OP_HASH160 <receiverPubKeyHash>
  // OP_ELSE
  //     <num> OP_CHECKSEQUENCEVERIFY OP_DROP OP_DUP OP_HASH160 <refundPubKeyHash>
  // OP_ENDIF
  // OP_EQUALVERIFY
  // OP_CHECKSIG
  const redeemScript = Buffer.alloc(113)
  redeemScript[0] = 99 // OP_IF
  redeemScript[1] = 168 // OP_SHA256
  for (let i=0; i < 32; i++) redeemScript[i+2] = digest[i]
  redeemScript[34] = 136 // OP_EQUALVERIFY
  redeemScript[35] = 118 // OP_DUP
  redeemScript[36] = 169 // OP_HASH160
  for (let i=0; i < 32; i++) redeemScript[i+36] = receiverPubKeyHash[i]
  redeemScript[69] = 103 // OP_ELSE
  for (let i=0; i < 4; i++) redeemScript[i+38] = locktimeBuffer[i] // TODO: Verify how this sequence number works
  redeemScript[74] = 178 // OP_CHECKSEQUENCEVERIFY
  redeemScript[75] = 117 // OP_DROP
  redeemScript[76] = 118 // OP_DUP
  redeemScript[77] = 169 // OP_HASH160
  for (let i=0; i < 32; i++) redeemScript[i+78] = refundPubKeyHash[i]
  redeemScript[110] = 104 // OP_ENDIF
  redeemScript[111] = 136 // OP_EQUALVERIFY
  redeemScript[112] = 172 // OP_CHECKSIG

  const redeemScriptHash = crypto.createHmac('ripemd160', crypto.createHmac('sha256', redeemScript).digest()).digest()

  return base58Check.encode(redeemScriptHash, '05')
}

function numberToBuffer(num) {
  return Buffer.from([
    (num >> 24) & 255,
    (num >> 16) & 255,
    (num >> 8) & 255,
    num & 255,
  ])
}
