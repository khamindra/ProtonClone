import getRandomValues from '@proton/get-random-values';
import { c } from 'ttag';
import { CryptoProxy } from '@proton/crypto';
import { arrayToHexString, binaryStringToArray } from '@proton/crypto/lib/utils';
import { API_CODES } from '../constants';
import { getDaysInMonth } from '../date-fns-utc';
import { encodeBase64URL, uint8ArrayToString } from '../helpers/encoding';
import {
    SyncMultipleApiResponses,
    SyncMultipleApiSuccessResponses,
    VcalDateOrDateTimeProperty,
    VcalDateTimeProperty,
} from '../interfaces/calendar';
import { ACTION_VIEWS, MAX_LENGTHS_API, MAXIMUM_DATE_UTC, MINIMUM_DATE_UTC } from './constants';
import { propertyToUTCDate } from './vcalConverter';
import { getIsPropertyAllDay } from './vcalHelper';

export const HASH_UID_PREFIX = 'sha1-uid-';
export const ORIGINAL_UID_PREFIX = '-original-uid-';

export const getIsSuccessSyncApiResponse = (
    response: SyncMultipleApiResponses
): response is SyncMultipleApiSuccessResponses => {
    const {
        Response: { Code, Event },
    } = response;
    return Code === API_CODES.SINGLE_SUCCESS && !!Event;
};

/**
 * Generates a calendar UID of the form 'RandomBase64String@proton.me'
 * RandomBase64String has a length of 28 characters
 */
export const generateProtonCalendarUID = () => {
    // by convention we generate 21 bytes of random data
    const randomBytes = getRandomValues(new Uint8Array(21));
    const base64String = encodeBase64URL(uint8ArrayToString(randomBytes));
    // and we encode them in base 64
    return `${base64String}@proton.me`;
};

export const generateVeventHashUID = async (binaryString: string, uid = '') => {
    const hash = arrayToHexString(
        await CryptoProxy.computeHash({ algorithm: 'unsafeSHA1', data: binaryStringToArray(binaryString) })
    );
    if (!uid) {
        return `${HASH_UID_PREFIX}${hash}`;
    }
    const sandwichedHash = `${HASH_UID_PREFIX}${hash}${ORIGINAL_UID_PREFIX}`;
    const uidLength = uid.length;
    const availableLength = MAX_LENGTHS_API.UID - sandwichedHash.length;
    const croppedUID = uid.substring(uidLength - availableLength, uidLength);
    return `${sandwichedHash}${croppedUID}`;
};

export const getOriginalUID = (uid = '') => {
    if (!uid) {
        return '';
    }
    const regexWithOriginalUid = new RegExp(`^${HASH_UID_PREFIX}[abcdef\\d]{40}${ORIGINAL_UID_PREFIX}(.+)`);
    const [, match] = uid.match(regexWithOriginalUid) || [];
    if (match) {
        return match;
    }
    const regexWithoutOriginalUid = new RegExp(`^${HASH_UID_PREFIX}[abcdef\\d]{40}$`);
    if (regexWithoutOriginalUid.test(uid)) {
        return '';
    }
    return uid;
};

export const getSupportedUID = (uid: string) => {
    const uidLength = uid.length;
    return uid.substring(uidLength - MAX_LENGTHS_API.UID, uidLength);
};

const getIsWellFormedDateTime = (property: VcalDateTimeProperty) => {
    return property.value.isUTC || !!property.parameters!.tzid;
};

export const getIsWellFormedDateOrDateTime = (property: VcalDateOrDateTimeProperty) => {
    return getIsPropertyAllDay(property) || getIsWellFormedDateTime(property);
};

export const getIsDateOutOfBounds = (property: VcalDateOrDateTimeProperty) => {
    const dateUTC: Date = propertyToUTCDate(property);
    return +dateUTC < +MINIMUM_DATE_UTC || +dateUTC > +MAXIMUM_DATE_UTC;
};

/**
 * Try to guess from the event uid if an event was generated by Proton. In pple there are two possibilities
 * * Old uids of the form 'proton-calendar-350095ea-4368-26f0-4fc9-60a56015b02e' and derived ones from "this and future" editions
 * * New uids of the form 'RandomBase64String@proton.me' and derived ones from "this and future" editions
 */
export const getIsProtonUID = (uid = '') => {
    return uid.endsWith('@proton.me') || uid.startsWith('proton-calendar-');
};

export const getDisplayTitle = (title = '') => {
    return title.trim() || c('Event title').t`(no title)`;
};

/**
 * Check whether an object has more keys than a set of keys.
 */
export const hasMoreThan = (set: Set<string>, properties: { [key: string]: any } = {}) => {
    return Object.keys(properties).some((key) => !set.has(key));
};

export const wrap = (res: string, prodId?: string) => {
    // Wrap in CRLF according to the rfc
    return prodId
        ? `BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:${prodId}\r\n${res}\r\nEND:VCALENDAR`
        : `BEGIN:VCALENDAR\r\nVERSION:2.0\r\n${res}\r\nEND:VCALENDAR`;
};

export const unwrap = (res: string) => {
    if (res.slice(0, 15) !== 'BEGIN:VCALENDAR') {
        return res;
    }
    const startIdx = res.indexOf('BEGIN:', 1);
    if (startIdx === -1 || startIdx === 0) {
        return '';
    }
    const endIdx = res.lastIndexOf('END:VCALENDAR');
    return res.slice(startIdx, endIdx).trim();
};

export const getPositiveSetpos = (date: Date) => {
    const dayOfMonth = date.getUTCDate();
    const shiftedDayOfMonth = dayOfMonth - 1;
    return Math.floor(shiftedDayOfMonth / 7) + 1;
};

export const getNegativeSetpos = (date: Date) => {
    const dayOfMonth = date.getUTCDate();
    const daysInMonth = getDaysInMonth(date);

    // return -1 if it's the last occurrence in the month
    return Math.ceil((dayOfMonth - daysInMonth) / 7) - 1;
};

export const reformatApiErrorMessage = (message: string) => {
    if (message.toLowerCase().endsWith('. please try again')) {
        return message.slice(0, -18);
    }
    return message;
};

export const getLinkToCalendarEvent = ({
    calendarID,
    eventID,
    recurrenceID,
}: {
    calendarID: string;
    eventID: string;
    recurrenceID?: number;
}) => {
    const params = new URLSearchParams();
    params.set('Action', ACTION_VIEWS.VIEW);
    params.set('EventID', eventID);
    params.set('CalendarID', calendarID);
    if (recurrenceID) {
        params.set('RecurrenceID', `${recurrenceID}`);
    }

    return `/event?${params.toString()}`;
};
