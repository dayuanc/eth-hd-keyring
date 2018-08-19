const EventEmitter = require('events').EventEmitter
const hdkey = require('ethereumjs-wallet/hdkey')
const bip39 = require('bip39')
var Hash = require("eth-lib/lib/hash");
const ethUtil = require('ethereumjs-util')
const sigUtil = require('eth-sig-util')
var RLP = require("eth-lib/lib/rlp");
var Bytes = require("eth-lib/lib/bytes");
var utils = require('./utils.js');

var Account = require("eth-lib/lib/account");
var Nat = require("eth-lib/lib/nat");
var cryp = (typeof global === 'undefined') ? require('crypto-browserify') : require('crypto');
var secp256k1 = require('secp256k1');
var Buffer = require('safe-buffer').Buffer;

var makeEven = function (hex) {
    if(hex.length % 2 === 1) {
        hex = hex.replace('0x', '0x0');
    }
    return hex;
};

// Options:
const hdPathString = `m/44'/60'/0'/0`
const type = 'HD Key Tree'

class HdKeyring extends EventEmitter {

  /* PUBLIC METHODS */

  constructor (opts = {}) {
    super()
    this.type = type
    this.deserialize(opts)
  }

  serialize () {
    return Promise.resolve({
      mnemonic: this.mnemonic,
      numberOfAccounts: this.wallets.length,
      hdPath: this.hdPath,
    })
  }

  deserialize (opts = {}) {
    this.opts = opts || {}
    this.wallets = []
    this.mnemonic = null
    this.root = null
    this.hdPath = opts.hdPath || hdPathString

    if (opts.mnemonic) {
      this._initFromMnemonic(opts.mnemonic)
    }

    if (opts.numberOfAccounts) {
      return this.addAccounts(opts.numberOfAccounts)
    }

    return Promise.resolve([])
  }

  addAccounts (numberOfAccounts = 1) {
    if (!this.root) {
      this._initFromMnemonic(bip39.generateMnemonic())
    }

    const oldLen = this.wallets.length
    const newWallets = []
    for (let i = oldLen; i < numberOfAccounts + oldLen; i++) {
      const child = this.root.deriveChild(i)
      const wallet = child.getWallet()
      newWallets.push(wallet)
      this.wallets.push(wallet)
    }
    const hexWallets = newWallets.map((w) => {
      return sigUtil.normalize(w.getAddress().toString('hex'))
    })
    return Promise.resolve(hexWallets)
  }

  getAccounts () {
    return Promise.resolve(this.wallets.map((w) => {
      return sigUtil.normalize(w.getAddress().toString('hex'))
    }))
  }

  // tx is an instance of the ethereumjs-transaction class.
signTransaction (address, tx) {
    const wallet = this._getWalletForAccount(address)
    var privateKey = wallet.getPrivateKey()
    //sign the TX with private key and return the signed HEX data
    // var signedTx = tx.sign(privKey)
    //Check the input fiels of the tx
        if (tx.chainId < 1) {
            return new Error('"Chain ID" is invalid');
        }

        console.log("chainid is: " + tx._chainId);

        if (!tx.gas && !tx.gasLimit) {
           return new Error('"gas" is missing');
        }

        if (tx.nonce  < 0 ||
            tx.gasLimit  < 0 ||
            tx.gasPrice  < 0 ||
            tx.chainId  < 0) {
            return new Error('Gas, gasPrice, nonce or chainId is lower than 0');
        }


        //Sharding Flag only accept the 
        //If input has not sharding flag, set it to 0 as global TX.
        if (tx.shardingFlag == undefined){
            // console.log("Set default sharding to 0");
            tx.shardingFlag = 0;
        }


        try {
            //Make sure all the number fields are in HEX format

            var transaction = tx;
            transaction.to = tx.to || '0x';//Can be zero, for contract creation
            transaction.data = tx.data || '0x';//can be zero for general TXs
            transaction.value = tx.value || '0x';//can be zero for contract call
            transaction.chainId = utils.numberToHex(tx._chainId);
            transaction.shardingFlag = utils.numberToHex(tx.shardingFlag);
            transaction.systemContract = '0x';//System contract flag, always = 0
            transaction.via = tx.via || '0x'; //Sharding subchain address

// console.log("TX:",transaction);
// for (var property in transaction) {
//   if (transaction.hasOwnProperty(property)) {
//     // do stuff
//                 var tmp = transaction[property];//System contract flag, always = 0
//             console.log("Encode:",property," value ", tmp, " to ", ethUtil.rlp.encode(tmp));

//   }
// }

            //Encode the TX for signature
            //   type txdata struct {
            // AccountNonce uint64          `json:"nonce"    gencodec:"required"`
            // SystemContract uint64          `json:"syscnt" gencodec:"required"`
            // Price        *big.Int        `json:"gasPrice" gencodec:"required"`
            // GasLimit     *big.Int        `json:"gas"      gencodec:"required"`
            // Recipient    *common.Address `json:"to"       rlp:"nil"` // nil means contract creation
            // Amount       *big.Int        `json:"value"    gencodec:"required"`
            // Payload      []byte          `json:"input"    gencodec:"required"`
            // ShardingFlag uint64 `json:"shardingFlag" gencodec:"required"`
            // Via            *common.Address `json:"to"       rlp:"nil"`

            // // Signature values
            // V *big.Int `json:"v" gencodec:"required"`
            // R *big.Int `json:"r" gencodec:"required"`
            // S *big.Int `json:"s" gencodec:"required"`

                var rlpEncoded = ethUtil.rlp.encode([
                transaction.nonce,
                transaction.systemContract,
                transaction.gasPrice,
                transaction.gasLimit,
                transaction.to,
                transaction.value,
                transaction.data,
                transaction.shardingFlag,
                transaction.via,
                transaction.chainId,
                "0x",
                "0x"]);


            var hash = Hash.keccak256(rlpEncoded);
            // for MOAC, keep 9 fields instead of 6
            var vPos = 9;
            //Sign the hash with the private key to produce the
            //V, R, S
            // var newsign = ethUtil.ecsign(hash, privateKey);// ethUtil.stripHexPrefix(privateKey));
            // console.log("newsign r:", newsign.r);//ethUtil.bufferToHex(newsign));
            // console.log("newsign s:", newsign.s);
            // console.log("newsign v:", newsign.v);
            hash = Buffer.from(makeEven(ethUtil.stripHexPrefix(hash)), 'hex')
            var newsign = ethUtil.ecsign(hash, ethUtil.stripHexPrefix(privateKey));
            var rawTx = ethUtil.rlp.decode(rlpEncoded).slice(0,vPos+3);

            //Replace the V field with chainID info
            var newV = newsign.v + 8 + transaction.chainId *2;

            // Add trimLeadingZero to avoid '0x00' after makeEven
            // dont allow uneven r,s,v values
            rawTx[vPos] = ethUtil.toBuffer(newV);//ethUtil.stripZeros(ethUtil.padToEven(ethUtil.bufferToHex(newV)));
            rawTx[vPos+1] = newsign.r;//ethUtil.stripZeros(ethUtil.padToEven(ethUtil.bufferToHex(newsign.r)));
            rawTx[vPos+2] = newsign.s;//ethUtil.stripZeros(ethUtil.padToEven(ethUtil.bufferToHex(newsign.s)));


            // var signedTx = ethUtil.rlp.encode(rawTx);
            var signedTx = '0xf8708080840bebc200834c4b4094fb743a2da25f457dad0ac155bf6c409185242d5b88115dd030eb16980000808081eda0d779e782e9143d955eb31fc113812ec0319f0e2153a0166de42227d36dbfca10a044e152491b7f8505f414cb2bd9fa864c862fbb806c8cb33a861ab5f8a335f77e';
        } catch(e) {

            return e;
        }

    return Promise.resolve(signedTx)
    // return ethUtil.bufferToHex(signedTx) //This only return a HEX string, 
  }

  // For eth_sign, we need to sign transactions:
  // hd
  signMessage (withAccount, data) {
    const wallet = this._getWalletForAccount(withAccount)
    const message = ethUtil.stripHexPrefix(data)
    var privKey = wallet.getPrivateKey()
    var msgSig = ethUtil.ecsign(new Buffer(message, 'hex'), privKey)
    var rawMsgSig = ethUtil.bufferToHex(sigUtil.concatSig(msgSig.v, msgSig.r, msgSig.s))
    return Promise.resolve(rawMsgSig)
  }

  // For personal_sign, we need to prefix the message:
  signPersonalMessage (withAccount, msgHex) {
    const wallet = this._getWalletForAccount(withAccount)
    const privKey = ethUtil.stripHexPrefix(wallet.getPrivateKey())
    const privKeyBuffer = new Buffer(privKey, 'hex')
    const sig = sigUtil.personalSign(privKeyBuffer, { data: msgHex })
    return Promise.resolve(sig)
  }

  // personal_signTypedData, signs data along with the schema
  signTypedData (withAccount, typedData) {
    const wallet = this._getWalletForAccount(withAccount)
    const privKey = ethUtil.toBuffer(wallet.getPrivateKey())
    const signature = sigUtil.signTypedData(privKey, { data: typedData })
    return Promise.resolve(signature)
  }

  // For eth_sign, we need to sign transactions:
  newGethSignMessage (withAccount, msgHex) {
    const wallet = this._getWalletForAccount(withAccount)
    const privKey = wallet.getPrivateKey()
    const msgBuffer = ethUtil.toBuffer(msgHex)
    const msgHash = ethUtil.hashPersonalMessage(msgBuffer)
    const msgSig = ethUtil.ecsign(msgHash, privKey)
    const rawMsgSig = ethUtil.bufferToHex(sigUtil.concatSig(msgSig.v, msgSig.r, msgSig.s))
    return Promise.resolve(rawMsgSig)
  }

  exportAccount (address) {
    const wallet = this._getWalletForAccount(address)
    return Promise.resolve(wallet.getPrivateKey().toString('hex'))
  }


  /* PRIVATE METHODS */

  _initFromMnemonic (mnemonic) {
    this.mnemonic = mnemonic
    const seed = bip39.mnemonicToSeed(mnemonic)
    this.hdWallet = hdkey.fromMasterSeed(seed)
    this.root = this.hdWallet.derivePath(this.hdPath)
  }


  _getWalletForAccount (account) {
    const targetAddress = sigUtil.normalize(account)
    return this.wallets.find((w) => {
      const address = sigUtil.normalize(w.getAddress().toString('hex'))
      return ((address === targetAddress) ||
              (sigUtil.normalize(address) === targetAddress))
    })
  }
}

HdKeyring.type = type
module.exports = HdKeyring
