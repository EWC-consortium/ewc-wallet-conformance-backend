import { webcrypto } from 'crypto';

const { subtle } = webcrypto;

// Function to generate a salt of a given length
const generateSalt = (length) => {
    const array = new Uint8Array(length);
    webcrypto.getRandomValues(array);
    return Buffer.from(array).toString('hex');
};

// Function to create a digest of the given data using the specified algorithm
const digest = async (data, algorithm = 'SHA-384') => {
    const encoder = new TextEncoder();
    const dataBuffer = encoder.encode(data);
    const hashBuffer = await subtle.digest(algorithm, dataBuffer);
    return new Uint8Array(hashBuffer);
};

const ES384 = {
    alg: 'ES384',
    // Function to generate a public/private key pair
    async generateKeyPair() {
        const keyPair = await subtle.generateKey(
            {
                name: 'ECDSA',
                namedCurve: 'P-384', // Use the P-384 curve for ES384
            },
            true, // Specify whether the key is extractable
            ['sign', 'verify'] // Key usages
        );
        const publicKeyJWK = await subtle.exportKey('jwk', keyPair.publicKey);
        const privateKeyJWK = await subtle.exportKey('jwk', keyPair.privateKey);
        return { publicKey: publicKeyJWK, privateKey: privateKeyJWK };
    },
    // Function to get a signer for the given private key
    async getSigner(privateKeyJWK) {
        const privateKey = await subtle.importKey(
            'jwk',
            privateKeyJWK,
            {
                name: 'ECDSA',
                namedCurve: 'P-384',
            },
            true, // You might consider making the key extractable for debugging
            ['sign']
        );
        
        return async (data) => {
            const encoder = new TextEncoder();
            const dataBuffer = encoder.encode(data);
            const signature = await subtle.sign(
                {
                    name: 'ECDSA',
                    hash: { name: 'SHA-384' }, // Use SHA-384 hash function
                },
                privateKey,
                dataBuffer
            );
            return Buffer.from(signature).toString('base64url');
        };
    },
    // Function to get a verifier for the given public key
    async getVerifier(publicKeyJWK) {
        const publicKey = await subtle.importKey(
            'jwk',
            publicKeyJWK,
            {
                name: 'ECDSA',
                namedCurve: 'P-384',
            },
            true, // The key is extractable
            ['verify']
        );
        return async (data, signatureBase64url) => {
            const encoder = new TextEncoder();
            const dataBuffer = encoder.encode(data);
            const signatureBuffer = Buffer.from(signatureBase64url, 'base64url');
            return await subtle.verify(
                {
                    name: 'ECDSA',
                    hash: { name: 'SHA-384' }, // Use SHA-384 hash function
                },
                publicKey,
                signatureBuffer,
                dataBuffer
            );
        };
    },
};

// Adjust the export syntax if necessary, depending on your module system
export { ES384, digest, generateSalt };
