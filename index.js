const crypto = require('crypto')
const secp256k1 = require('secp256k1')

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

console.log(receiverPubKeyHash, refundPubKeyHash)

function generateBIP199Address(receiverPubKeyHash, refundPubKeyHash) {

}
