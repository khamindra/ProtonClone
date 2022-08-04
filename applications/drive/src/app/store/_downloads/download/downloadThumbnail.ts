// @ts-ignore missing `toStream` TS defs
import { readToEnd, toStream } from '@openpgp/web-stream-tools';
import { ReadableStream } from 'web-streams-polyfill';

import { CryptoProxy, VERIFICATION_STATUS } from '@proton/crypto';

import { streamToBuffer } from '../../../utils/stream';
import { DecryptFileKeys } from '../interface';
import downloadBlock from './downloadBlock';

type GetKeysCallback = () => Promise<DecryptFileKeys>;

export default async function downloadThumbnail(url: string, token: string, getKeys: GetKeysCallback) {
    const abortController = new AbortController();
    const stream = await downloadBlock(abortController, url, token);
    const { data: decryptedStream, verifiedPromise } = await decryptThumbnail(stream, getKeys);
    const thumbnailData = streamToBuffer(decryptedStream);
    return {
        abortController,
        contents: thumbnailData,
        verifiedPromise,
    };
}

async function decryptThumbnail(
    stream: ReadableStream<Uint8Array>,
    getKeys: GetKeysCallback
): Promise<{ data: ReadableStream<Uint8Array>; verifiedPromise: Promise<VERIFICATION_STATUS> }> {
    const { sessionKeys, addressPublicKeys } = await getKeys();

    const { data, verified } = await CryptoProxy.decryptMessage({
        binaryMessage: await readToEnd(stream),
        sessionKeys,
        verificationKeys: addressPublicKeys,
        format: 'binary',
        // Some old keys seem to have been generated with device time instead of server time,
        // resulting in the signature having time in the future compared to them,
        // thus failing verification
        // @ts-ignore missing field in config declarations (TODO lara)
        config: { allowInsecureVerificationWithReformattedKeys: true },
    });
    return {
        data: toStream(data) as ReadableStream<Uint8Array>,
        verifiedPromise: Promise.resolve(verified), // TODO lara/michal: refactor this since we no longer use streaming on decryption, hence verified is no longer a promise
    };
}
