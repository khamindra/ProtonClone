import { Draft } from 'immer';

import { Message } from '@proton/shared/lib/interfaces/mail/Message';

import { RootState } from '../../store';
import { localID as localIDSelector, messageByID } from '../messagesSelectors';
import { MessagesState } from '../messagesTypes';

/**
 * Only takes technical stuff from the updated message
 */
export const mergeSavedMessage = (messageSaved: Draft<Message>, messageReturned: Message) => {
    Object.assign(messageSaved, {
        ID: messageReturned.ID,
        Time: messageReturned.Time,
        ConversationID: messageReturned.ConversationID,
        LabelIDs: messageReturned.LabelIDs,
    });
};

export const getLocalID = (state: Draft<MessagesState>, ID: string) =>
    localIDSelector({ messages: state } as RootState, { ID });

export const getMessage = (state: Draft<MessagesState>, ID: string) =>
    messageByID({ messages: state } as RootState, { ID });
