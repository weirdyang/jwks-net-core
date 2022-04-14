const jose = require('node-jose');
const {readFile} = require('fs/promises');
const path = require('path');

const signKeyFile = () => readFile(path.resolve(__dirname,'signing','private.pem'), 'utf8');
const verifyKeyFile = () =>  readFile(path.resolve(__dirname,'signing', 'public.pem'), 'utf8');

const encryptFile = () =>  readFile(path.resolve(__dirname, 'encrypting', 'private.pem'), 'utf8');
const dencryptFile = () => readFile(path.resolve(__dirname, 'encrypting','public.pem'), 'utf8');

const signProps = {
    kid: 'signing-keys',
    alg: 'ES256',
    use: 'sig',
}

const encProps = {
    kid: 'enc-keys',
    alg: 'ECDH-ES+A256KW',
    use: 'enc',
}

const keyStore = jose.JWK.createKeyStore();

const readCerts = async () => {
    const signData = await signKeyFile();
    const signKey = await jose.JWK.asKey(signData, 'pem', signProps);
    await keyStore.add(signKey);

    // this part is actually not needed 
    // as private key includes public
    // and will result in a duplicate public key
    const verifyData = await verifyKeyFile();
    const verifyKey = await jose.JWK.asKey(verifyData, 'pem', signProps);
    await keyStore.add(verifyKey);

    const encData = await encryptFile();
    const encKey = await jose.JWK.asKey(encData, 'pem', encProps);
    await keyStore.add(encKey);
    console.dir(encKey);

    // this part is actually not needed 
    // as private key includes public
    // and will result in a duplicate public key
    const decData = await dencryptFile();
    const decKey = await jose.JWK.asKey(decData, 'pem', encProps);
    await keyStore.add(decKey);

    console.log(keyStore.toJSON());
    console.log(keyStore.all().length);
    
}
readCerts();