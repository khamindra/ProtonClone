import { CryptoProxy } from '@proton/crypto';

import { activateKeyRoute, activateKeyRouteV2 } from '../api/keys';
import { MEMBER_PRIVATE } from '../constants';
import { Address, Api, DecryptedKey, UserModel as tsUserModel } from '../interfaces';
import { generateAddressKeyTokens } from './addressKeys';
import { getActiveKeys, getNormalizedActiveKeys } from './getActiveKeys';
import { getPrimaryKey } from './getPrimaryKey';
import { getHasMigratedAddressKeys } from './keyMigration';
import { getSignedKeyList } from './signedKeyList';

export const getAddressesWithKeysToActivate = (user: tsUserModel, addresses: Address[]) => {
    // If signed in as subuser, or not a readable member
    if (!user || !addresses || user.OrganizationPrivateKey || user.Private !== MEMBER_PRIVATE.READABLE) {
        return [];
    }
    return addresses.filter(({ Keys = [] }) => {
        return Keys.some(({ Activation }) => !!Activation);
    });
};

interface Args {
    address: Address;
    addresses: Address[];
    addressKeys: DecryptedKey[];
    userKeys: DecryptedKey[];
    keyPassword: string;
    api: Api;
}

export const activateMemberAddressKeys = async ({
    addresses,
    address,
    addressKeys,
    userKeys,
    keyPassword,
    api,
}: Args) => {
    if (!addressKeys.length) {
        return;
    }
    if (!keyPassword) {
        throw new Error('Password required to generate keys');
    }

    const activeKeys = getNormalizedActiveKeys(
        address,
        await getActiveKeys(address, address.SignedKeyList, address.Keys, addressKeys)
    );

    const primaryUserKey = getPrimaryKey(userKeys)?.privateKey;
    if (!primaryUserKey) {
        throw new Error('Missing primary user key');
    }

    const isKeyMigrationFlow = getHasMigratedAddressKeys(addresses);

    for (const addressKey of addressKeys) {
        const { ID, privateKey } = addressKey;
        const Key = address.Keys.find(({ ID: otherID }) => otherID === ID);
        if (!Key?.Activation || !privateKey) {
            continue;
        }
        if (isKeyMigrationFlow) {
            const { token, encryptedToken, signature } = await generateAddressKeyTokens(primaryUserKey);
            const encryptedPrivateKey = await CryptoProxy.exportPrivateKey({
                privateKey,
                passphrase: token,
            });
            const SignedKeyList = await getSignedKeyList(activeKeys);

            await api(
                activateKeyRouteV2({
                    ID,
                    PrivateKey: encryptedPrivateKey,
                    SignedKeyList,
                    Token: encryptedToken,
                    Signature: signature,
                })
            );
        } else {
            const encryptedPrivateKey = await CryptoProxy.exportPrivateKey({
                privateKey,
                passphrase: keyPassword,
            });
            const SignedKeyList = await getSignedKeyList(activeKeys);

            await api(activateKeyRoute({ ID, PrivateKey: encryptedPrivateKey, SignedKeyList }));
        }
    }
};
