// import CryptoJS, { SHA256 } from 'crypto-js';
import elliptic from 'elliptic';
import IdIterator from 'json-rpc-random-id';


const EdDSA = elliptic.eddsa;
const URL_PREFIX = 'https://';

export const SUPPORTED_NETWORK_CHAINIDS = {
  MAINNET: '0x1',
  BSC: '0x38',
  OPTIMISM: '0xa',
  POLYGON: '0x89',
  AVALANCHE: '0xa86a',
  ARBITRUM: '0xa4b1',
  LINEA_MAINNET: '0xe708',
};

export const blockaidValidationSupportedForNetwork = (
  chainId: string,
): boolean => {
  return Object.values(SUPPORTED_NETWORK_CHAINIDS).some(
    (cid) => cid === chainId,
  );
};

export const IdGenerator = IdIterator();

export const createPayload = (
  method: string,
  params: Record<string, unknown>,
) => ({
  id: IdGenerator(),
  jsonrpc: '2.0',
  method,
  params: params || [],
});

export const PROVIDER_ERRORS = {
  limitExceeded: () => ({
    jsonrpc: '2.0',
    id: IdGenerator(),
    error: {
      code: -32005,
      message: 'Limit exceeded',
    },
  }),
  methodNotSupported: () => ({
    jsonrpc: '2.0',
    id: IdGenerator(),
    error: {
      code: -32601,
      message: 'Method not supported',
    },
  }),
};

const getHash = async (data: ArrayBuffer, useNative: boolean): Promise<any> => {
  if (
    'crypto' in globalThis &&
    typeof globalThis.crypto === 'object' &&
    globalThis.crypto.subtle?.digest &&
    useNative
  ) {
    const hashBuffer = await globalThis.crypto.subtle.digest('SHA-256', data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    const hash = hashArray
      .map((item) => item.toString(16).padStart(2, '0'))
      .join('');
    return hash;
  }

  return (globalThis.Crypto as any).createHash('sha256').update(data).digest('hex');

};

// useNative argument is added for testing purpose, without it test cases are breaking in Node-20 and above
// Reason being that in node 20 crypto is always present in globalThis
// and it is not possible to reset it due to security reasons
export const validateSignature = async (
  data: ArrayBuffer,
  hashSignature: string,
  key: string,
  filePath: string,
  useNative = true,
) => {
  let time = Date.now();
  const hashString = await getHash(data, useNative);
  console.log(`Time taken to get hash: ${Date.now() - time}ms`);
  // const hashString = hash.toString();
  time = Date.now();
  const ec = new EdDSA('ed25519');
  console.log(`Time taken to create EdDSA: ${Date.now() - time}ms`);

  time = Date.now();
  const ecKey = ec.keyFromPublic(key);
  console.log(`Time taken to create ecKey: ${Date.now() - time}ms`);

  time = Date.now();
  // eslint-disable-next-line no-restricted-globals
  const result = ecKey.verify(Buffer.from(hashString), hashSignature);
  console.log(`Time taken to verify signature: ${Date.now() - time}ms`);
  if (!result) {
    throw Error(`Signature verification failed for file path: ${filePath}`);
  }
};

export const constructURLHref = (base: string, path: string): string =>
  new URL(
    `${URL_PREFIX}${base}/${path}`
      .replace(/https:\/\/https:\/\//gu, 'https://')
      .replace(/\/\//gu, '/'),
  ).href;

export const addHexPrefix = (str: string) => {
  if (typeof str !== 'string' || str.match(/^-?0x/u)) {
    return str;
  }

  if (str.match(/^-?0X/u)) {
    return str.replace('0X', '0x');
  }

  return `0x${str}`;
};

/*
 * The function check to ensure that file path can contain only alphanumeric
 * characters and a dot character (.) or slash (/).
 */
export const checkFilePath = (filePath: string): void => {
  const filePathRegex = /^[\w./]+$/u;
  if (!filePath.match(filePathRegex)) {
    throw new Error(`Invalid file path for data file: ${filePath}`);
  }
};
