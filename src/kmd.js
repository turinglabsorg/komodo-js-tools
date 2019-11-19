import _ from 'lodash'
var CoinKey = require('coinkey')
var crypto = require('crypto')
const CryptoJS = require('crypto-js')
const secp256k1 = require('secp256k1')
var cs = require('coinstring')
var axios = require('axios')
import Trx from './trx/trx.js'

const kmdInfo = {
    private: 0xbc,
    public: 0x3c,
    scripthash: 0x55
};

export default class KMDJS {
    constructor (){
        this.RAWsAPIKey = '';
        this.PubAddress = '';
        KMDJS.clearCache()
    }

    //IDANODE FUNCTIONS
    static returnNodes(){
        return ['http://localhost:777'];
    }
    
    static async checkNode(node){
        return new Promise(response => {
            axios.get(node + '/wallet/getinfo').catch(err => {
                response(false)
            }).then(result => {
                response(result)
            })
        })
    }

    static async connectNode(){
        return new Promise(async response => {
            var checknodes = this.returnNodes()
            var connected = false
            while(connected === false){
                var checknode = checknodes[Math.floor(Math.random()*checknodes.length)];
                const check = await this.checkNode(checknode)
                if(check !== false){
                    connected = true
                    response(checknode)
                }
            }
        })
    }

    //CACHE FUNCTIONS
    static async clearCache(){
        return new Promise(async response => {
            await localStorage.removeItem('TXIDCache')
            await localStorage.removeItem('UTXOCache')
            response(true)
        })
    }

    static async returnTXIDCache(){
        return new Promise(async response => {
            var cache = await localStorage.getItem('TXIDCache')
            if(cache === null){
                cache = []
            }else{
                cache = JSON.parse(cache)
            }
            response(cache)
        })
    }

    static async pushTXIDtoCache(txid){
        return new Promise(async response => {
            let cache = await this.returnTXIDCache()
            cache.push(txid)
            await localStorage.setItem('TXIDCache',JSON.stringify(cache))
            response(true)
        })
    }

    static async returnUTXOCache(){
        return new Promise(async response => {
            var cache = await localStorage.getItem('UTXOCache')
            if(cache === null){
                cache = []
            }else{
                cache = JSON.parse(cache)
            }
            response(cache)
        })
    }

    static async pushUTXOtoCache(utxo){
        return new Promise(async response => {
            let cache = await this.returnUTXOCache()
            cache.push(utxo)
            await localStorage.setItem('UTXOCache',JSON.stringify(cache))
            response(true)
        })
    }

    //CRYPT AND ENCRYPT FUNCTIONS
    static async cryptData(data, password){
        return new Promise(response => {
            const cipher = crypto.createCipher('aes-256-cbc', password)
            let hex = cipher.update(JSON.stringify(data), 'utf8', 'hex')
            hex += cipher.final('hex')
            response(hex)
        })
    }

    static async decryptData(data, password){
        return new Promise(response => {
            try{
                var decipher = crypto.createDecipher('aes-256-cbc', password)
                var dec = decipher.update(data,'hex','utf8')
                dec += decipher.final('utf8')
                response(JSON.parse(dec))
            }catch(e){
                response(false)
            }
        })
    }

    //ADDRESS MANAGEMENT
    static async createAddress(password, saveKey = true){
        // LYRA WALLET
        var ck = new CoinKey.createRandom(kmdInfo)
                
        var kmdpub = ck.publicAddress;
        var kmdprv = ck.privateWif;
        var kmdkey = ck.publicKey.toString('hex');
        
        // STORE JUST LYRA WALLET 
        var wallet = {
            prv: kmdprv,
            key: kmdkey
        }

        var walletstore = await this.buildWallet(password, kmdpub, wallet, saveKey)
        
        var response = {
            pub: kmdpub,
            key: kmdkey,
            prv: kmdprv,
            walletstore: walletstore
        }
        return response;
    }

    static async buildWallet(password, pub, wallet, saveKey){
        return new Promise(response => {

            const cipher = crypto.createCipher('aes-256-cbc', password);
            let wallethex = cipher.update(JSON.stringify(wallet), 'utf8', 'hex');
            wallethex += cipher.final('hex');

            var walletstore = pub + ':' + wallethex;
            
            if(saveKey == true){
                localStorage.setItem('SID',walletstore)
            }

            response(walletstore)
        })
    }

    static async initAddress(address){
        const app = this
        const node = await app.connectNode();
        const response = await axios.post(node + '/init', {address: address, airdrop: true})
        return response;
    }

    static async getPublicKey(privateWif){
        var ck = new CoinKey.fromWif(privateWif);
        var pubkey = ck.publicKey.toString('hex');
        return pubkey;
    }

    static async getAddressFromPubKey(pubKey){
        return new Promise(response => {
            let pubkeybuffer = new Buffer(pubKey,'hex')
            var sha = crypto.createHash('sha256').update(pubkeybuffer).digest()
            let pubKeyHash = crypto.createHash('rmd160').update(sha).digest()
            var hash160Buf = new Buffer(pubKeyHash, 'hex')
            response(cs.encode(hash160Buf, kmdInfo.public)) 
        })
    }

    //BROWSER KEY MANAGEMENT
    static async saveKey(sid){
        localStorage.setItem('SID',sid)
        return Promise.resolve(true);
    }

    static keyExist(){
        var SID = localStorage.getItem('SID')
        if(SID !== null && SID !== '' && SID !== undefined){
            var SIDS = SID.split(':');
            if(SIDS[0].length > 0){
                this.PubAddress = SIDS[0];
                this.RAWsAPIKey = SIDS[1];
                return SIDS[0];
            } else {
                return false
            }
        }else{
            return false
        }
    }

    static async readKey(password, key = ''){
        if(key === ''){
            var SID = localStorage.getItem('SID')
        }else{
            var SID = key;
        }
        if(password !== ''){
            var SIDS = SID.split(':');
            try {
                var decipher = crypto.createDecipher('aes-256-cbc', password);
                var dec = decipher.update(SIDS[1],'hex','utf8');
                dec += decipher.final('utf8');
                var decrypted = JSON.parse(dec);
                return Promise.resolve(decrypted);
            } catch (ex) {
                //console.log('WRONG PASSWORD')
                return Promise.resolve(false);
            }
        }
    }

    static forgetKey(){
        localStorage.setItem('SID','')
        return true;
    }

    //TRANSACTIONS FUNCTIONS
    static async listUnspent(address){
        const app = this
        const node = await app.connectNode();
        var unspent = await axios.get(node + '/unspent/' + address)
        return unspent.data.unspent
    }

    static async sendRawTransaction(rawtransaction){
        const app = this
        const node = await app.connectNode();
        if(node !== undefined && rawtransaction !== undefined){
            var txid = await axios.post(
                node + '/sendrawtransaction',
                { rawtransaction: rawtransaction }
            ).catch(function(err){
                console.log(err)
            })
            return txid.data.data
        } else {
            return Promise.resolve(false)
        }
    }

    static async decodeRawTransaction(rawtransaction){
        const app = this
        const node = await app.connectNode();
        if(node !== undefined){
            var transaction = await axios.post(
                node + '/decoderawtransaction',
                { rawtransaction: rawtransaction }
            ).catch(function(err){
                console.log(err)
            })
            return transaction.data.transaction
        } else {
            return Promise.resolve(false)
        }
    }

    static async build(password, send = false, to, amount, metadata = '', fees = 0.001, key){
        var SID = key;
        if(password !== ''){
            var SIDS = SID.split(':');
            try {
                var decipher = crypto.createDecipher('aes-256-cbc', password);
                var dec = decipher.update(SIDS[1],'hex','utf8');
                dec += decipher.final('utf8');
                var decrypted = JSON.parse(dec);

                var trx = Trx.transaction();
                var from = SIDS[0]
                var unspent = []
                var inputs = []
                var cache = await this.returnUTXOCache()
                //console.log('CACHE', cache)
                if(cache.length > 0){
                    for(var x = 0; x < cache.length; x++){
                        unspent.push(cache[x])
                    }
                }
                //var listunspent = await this.listUnspent(from)
                var listunspent = [
                    {
                        "amount": 0.20000000,
                        "vout": 0,
                        "scriptPubKey": "76a914e01ed865affaa8eee850451815cba6b2f4ba291188ac",
                        "txid": "4046e865e56c2f1e1cdc79af5cb9fdd03ec4181a914c9dbc2d44e27887114f82"
                    }
                ]
                // createrawtransaction [{"txid":"4046e865e56c2f1e1cdc79af5cb9fdd03ec4181a914c9dbc2d44e27887114f82","vout":0,"scriptPubKey":"76a914e01ed865affaa8eee850451815cba6b2f4ba291188ac"}] {"RNDGt6v4mhH6enmUfvzu1oWYtn9AbtdujX":0.01,"RViEPexN8ZMjnKr5F4mvGHD5AM7qcic1Yd":0.199}
                // signrawtransaction 0100000001824f118778e2442dbc9d4c911a18c43ed0fdb95caf79dc1c1e2f6ce565e846400000000000ffffffff0240420f00000000001976a9148ddbfb1a25eed244fd697b26d570edb514c9db0588ac60a62f01000000001976a914e01ed865affaa8eee850451815cba6b2f4ba291188ac00000000 [{"txid":"4046e865e56c2f1e1cdc79af5cb9fdd03ec4181a914c9dbc2d44e27887114f82","vout":0,"scriptPubKey":"76a914e01ed865affaa8eee850451815cba6b2f4ba291188ac"}] ["Uvp5PxBQgLW6D1TZF44rZ5YfGRTTHYnASEp9NaRNcdDE1xdJuE1s"]
                // sendrawtransaction 0100000001824f118778e2442dbc9d4c911a18c43ed0fdb95caf79dc1c1e2f6ce565e84640000000006a4730440220031a19db3cab7e47dc74b52145776190c010e27afc1a82c8a7b60365bae792df02201fded21ae7f0c757bb7626761d9aaf108b3f47749ca91a3b42c7f5ea3b6897590121038a1f158126995b68f98e6e5a2f4f104b1c88cb09e8e3f6800f0c968a871b81c4ffffffff0240420f00000000001976a9148ddbfb1a25eed244fd697b26d570edb514c9db0588ac60a62f01000000001976a914e01ed865affaa8eee850451815cba6b2f4ba291188ac00000000
                for(var x = 0; x < listunspent.length; x++){
                    unspent.push(listunspent[x])
                }
                //console.log('UNSPENT', unspent)
                if(unspent.length > 0){
                    var inputamount = 0;
                    var amountneed = amount + fees;
                    for (var i=0; i < unspent.length; i++){
                        if(inputamount <= amountneed){
                            var txid = unspent[i]['txid'];
                            var index = unspent[i]['vout'];
                            var script = unspent[i]['scriptPubKey'];
                            var cache = await this.returnTXIDCache()
                            if(cache.indexOf(txid + ':' + index) === -1 && inputs.indexOf(txid + ':' + index) === -1){
                                trx.addinput(txid,index,script);
                                inputamount += unspent[i]['amount']
                                inputs.push(txid + ':' + index)
                            }
                        }
                    }
                    if(inputamount >= amountneed){
                        var change = inputamount - amountneed;
                        if(amount > 0.00001){
                            trx.addoutput(to,amount);
                        }
                        if(change > 0.00001){
                            trx.addoutput(from,change);
                        }
                        if(metadata !== ''){
                            if(metadata.length <= 80){
                                //console.log('ADDING METADATA TO TX', metadata)
                                trx.addmetadata(metadata);
                            }else{
                                //console.log('METADATA TOO LONG')
                            }
                        }
                        var wif = decrypted.prv;
                        var signed = trx.sign(wif,1);
                        if(send === false){
                            return Promise.resolve({
                                inputs: inputs,
                                signed: signed
                            });
                        } else {
                            var txid = await this.sendRawTransaction(signed)
                            if(txid !== null && txid.length === 64){
                                for(let i in inputs){
                                    await this.pushTXIDtoCache(inputs[i])
                                }
                                //console.log("TX SENT: " + txid)
                                return Promise.resolve(txid)
                            }
                        }
                    }else{
                        //console.log('NOT ENOUGH FUNDS')
                        return Promise.resolve(false) //NOT ENOUGH FUNDS
                    }
                } else {
                    //console.log('NO UNSPENTS')
                    return Promise.resolve(false) //NOT ENOUGH FUNDS
                }
            } catch (error) {
                //console.log(error)
                return Promise.resolve(false);
            }
        }
    }

    static async send(password, to, amount, metadata = '', key = ''){
        if(key === ''){
            var SID = localStorage.getItem('SID');
        }else{
            var SID = key;
        }
        if(password !== '' && to !== ''){
            var SIDS = SID.split(':');
            try {
                var decipher = crypto.createDecipher('aes-256-cbc', password);
                var dec = decipher.update(SIDS[1],'hex','utf8');
                dec += decipher.final('utf8');

                var txid = ''
                var i = 0
                var rawtransaction
                while(txid !== null && txid !== undefined && txid.length !== 64){
                    var fees = 0.001 + (i / 1000)
                    rawtransaction = await this.build(password,false,to,amount,metadata,fees,SID)
                    //console.log(rawtransaction)
                    txid = await this.sendRawTransaction(rawtransaction.signed)
                    //console.log(txid)
                    if(txid !== null && txid !== false && txid.length === 64){
                        for(let i in rawtransaction.inputs){
                            await this.pushTXIDtoCache(rawtransaction.inputs[i])
                        }
                        //Storing UTXO to cache
                        var decoded = await this.decodeRawTransaction(rawtransaction.signed)
                        if(decoded.vout[1].scriptPubKey.addresses !== undefined){
                            let unspent = {
                                txid: decoded.txid,
                                vout: 1, 
                                address: decoded.vout[1].scriptPubKey.addresses[0],
                                scriptPubKey: decoded.vout[1].scriptPubKey.hex,
                                amount: decoded.vout[1].value
                            }
                            await this.pushUTXOtoCache(unspent)
                        }
                    }else{
                        txid = null
                    }
                    i++;
                }
                return Promise.resolve(txid)
            }catch(e){
                return Promise.resolve(false)
            }
        }
    }

    //SIGNING FUNCTIONS
    static async signMessage(key, message){
        return new Promise(response => {
            //CREATING CK OBJECT
            var ck = CoinKey.fromWif(key, kmdInfo);
            //CREATE HASH FROM MESSAGE
            let hash = CryptoJS.SHA256(message);
            let msg = Buffer.from(hash.toString(CryptoJS.enc.Hex), 'hex');
            //GETTING PUBKEY FROM PRIVATEKEY
            let privKey = ck.privateKey
            //SIGN MESSAGE
            const sigObj = secp256k1.sign(msg, privKey)
            const pubKey = secp256k1.publicKeyCreate(privKey)

            response({
                message: message,
                hash: hash.toString(CryptoJS.enc.Hex),
                signature: sigObj.signature.toString('hex'),
                pubkey: pubKey.toString('hex'),
                address: ck.publicAddress
            })
        })
    }

    static async verifyMessage(pubkey, signature, message){
        return new Promise(async response => {
            //CREATE HASH FROM MESSAGE
            let hash = CryptoJS.SHA256(message);
            let msg = Buffer.from(hash.toString(CryptoJS.enc.Hex), 'hex')
            //VERIFY MESSAGE
            let buf = Buffer.from(signature,'hex')
            let pubKey = Buffer.from(pubkey,'hex')
            let verified = secp256k1.verify(msg, buf, pubKey)
            let address = await this.getAddressFromPubKey(pubkey)
            if(verified === true){
                response({
                    address: address,
                    pubkey: pubkey,
                    signature: signature,
                    hash: hash.toString(CryptoJS.enc.Hex),
                    message: message,
                })
            }else{
                response(false)
            }
        })
    }
}
new KMDJS
window.KMDJS = KMDJS
