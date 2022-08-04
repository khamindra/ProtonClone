import { ReadableStream } from 'web-streams-polyfill';
import { CryptoProxy, VERIFICATION_STATUS } from '@proton/crypto';
// @ts-ignore missing `toStream` TS definitions
import { readToEnd, toStream } from '@openpgp/web-stream-tools';

import { LinkDownload, DownloadCallbacks, DownloadStreamControls, DecryptFileKeys } from '../interface';
import initDownloadBlocks from './downloadBlocks';

/**
 * initDownloadLinkFile prepares controls to download the provided file.
 * This epxects only file blocks, not thumbnail block, thus detached
 * signature is required. To download thumbnail, use thumbnail helper.
 */
export default function initDownloadLinkFile(link: LinkDownload, callbacks: DownloadCallbacks): DownloadStreamControls {
    let keysPromise: Promise<DecryptFileKeys> | undefined;

    const checkFileSignatures = async (abortSignal: AbortSignal) => {
        if (link.signatureIssues) {
            await callbacks.onSignatureIssue?.(abortSignal, link, link.signatureIssues);
        }
    };

    const transformBlockStream = async (
        abortSignal: AbortSignal,
        stream: ReadableStream<Uint8Array>,
        encSignature: string
    ) => {
        if (!keysPromise) {
            keysPromise = callbacks.getKeys(abortSignal, link.shareId, link.linkId);
        }

        const keys = await keysPromise;
        const { data: decryptedSignature } = await CryptoProxy.decryptMessage({
            armoredMessage: encSignature,
            decryptionKeys: keys.privateKey,
            format: 'binary',
        });

        const { data, verified } = await CryptoProxy.decryptMessage({
            binaryMessage: await readToEnd(stream),
            binarySignature: decryptedSignature,
            sessionKeys: keys.sessionKeys,
            verificationKeys: keys.addressPublicKeys,
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
    };

    const checkBlockSignature = async (abortSignal: AbortSignal, verifiedPromise: Promise<VERIFICATION_STATUS>) => {
        const verified = await verifiedPromise;
        if (verified !== VERIFICATION_STATUS.SIGNED_AND_VALID) {
            await callbacks.onSignatureIssue?.(abortSignal, link, { blocks: verified });
        }
    };

    const controls = initDownloadBlocks(link.name, {
        ...callbacks,
        checkFileSignatures,
        getBlocks: (abortSignal, pagination) => callbacks.getBlocks(abortSignal, link.shareId, link.linkId, pagination),
        transformBlockStream,
        checkBlockSignature,
        onProgress: (bytes: number) => callbacks.onProgress?.([link.linkId], bytes),
    });
    return {
        ...controls,
        start: () => {
            const linkSizes = Object.fromEntries([[link.linkId, link.size]]);
            callbacks.onInit?.(link.size, linkSizes);
            return controls.start();
        },
    };
}
