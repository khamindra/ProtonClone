import { useState } from 'react';
import { OpenPGPKey } from 'pmcrypto';

import { useHandler, useNotifications } from '@proton/components';
import { Attachment } from '@proton/shared/lib/interfaces/mail/Message';
import { getAttachments, isPlainText } from '@proton/shared/lib/mail/messages';

import { MessageState, MessageStateWithData } from '../../logic/messages/messagesTypes';
import {
    createEmbeddedImageFromUpload,
    isEmbeddable,
    matchSameCidOrLoc,
    readContentIDandLocation,
} from '../../helpers/message/messageEmbeddeds';
import { getEmbeddedImages, updateImages } from '../../helpers/message/messageImages';
import { MessageChange } from '../../components/composer/Composer';
import { EditorActionsRef } from '../../components/composer/editor/SquireEditorWrapper';
import { ATTACHMENT_ACTION, checkSize, uploadEO } from '../../helpers/attachment/attachmentUploader';

interface Props {
    message: MessageState;
    onChange: MessageChange;
    editorActionsRef: EditorActionsRef;
    publicKey?: OpenPGPKey[];
}

export const useEOAttachments = ({ message, onChange, editorActionsRef, publicKey }: Props) => {
    const { createNotification } = useNotifications();

    const [imagesToInsert, setImagesToInsert] = useState<File[]>([]);

    /**
     * Start uploading a file, the choice between attachment or inline is done.
     */
    const handleAddAttachmentsUpload = useHandler(async (action: ATTACHMENT_ACTION, files: File[] = []) => {
        if (publicKey) {
            files.forEach((file: File) => {
                uploadEO(file, message as MessageStateWithData, publicKey, action).then(({ attachment, packets }) => {
                    // Warning, that change function can be called multiple times, don't do any side effect in it
                    onChange((message: MessageState) => {
                        // New attachment list
                        const Attachments = [...getAttachments(message.data), attachment];
                        const embeddedImages = getEmbeddedImages(message);

                        if (action === ATTACHMENT_ACTION.INLINE) {
                            embeddedImages.push(createEmbeddedImageFromUpload(attachment));
                        }

                        const messageImages = updateImages(message.messageImages, undefined, undefined, embeddedImages);

                        return { data: { Attachments }, messageImages };
                    });

                    if (action === ATTACHMENT_ACTION.INLINE) {
                        editorActionsRef.current?.insertEmbedded(attachment, packets.Preview);
                    }
                });
            });
        }
    });

    /**
     * Entry point for upload, will check and ask for attachment action if possible
     */
    const handleAddAttachments = useHandler(async (files: File[]) => {
        const embeddable = files.every((file) => isEmbeddable(file.type));
        const plainText = isPlainText(message.data);

        if (checkSize(createNotification, message, files)) {
            return;
        }

        if (!plainText && embeddable) {
            setImagesToInsert(files);
        } else {
            void handleAddAttachmentsUpload(ATTACHMENT_ACTION.ATTACHMENT, files);
        }
    });

    /**
     * Remove an existing attachment, deal with potential embedded image
     */
    const handleRemoveAttachment = useHandler(async (attachment: Attachment) => {
        onChange((message: MessageState) => {
            const Attachments = message.data?.Attachments?.filter((a: Attachment) => a.ID !== attachment.ID) || [];

            const { cid, cloc } = readContentIDandLocation(attachment);
            const embeddedImages = getEmbeddedImages(message);
            const embeddedImage = embeddedImages.find((image) => matchSameCidOrLoc(image, cid, cloc));
            const newEmbeddedImages = embeddedImages.filter((image) => !matchSameCidOrLoc(image, cid, cloc));

            if (embeddedImage) {
                setTimeout(() => {
                    editorActionsRef.current?.removeEmbedded(embeddedImage.attachment);
                });
            }

            const messageImages = updateImages(message.messageImages, undefined, undefined, newEmbeddedImages);

            return { data: { Attachments }, messageImages };
        });
    });

    const handleUploadImage = (action: ATTACHMENT_ACTION) => {
        void handleAddAttachmentsUpload(action, imagesToInsert);
        setImagesToInsert([]);
    };

    return {
        imagesToInsert,
        setImagesToInsert,
        handleAddAttachments,
        handleAddAttachmentsUpload,
        handleRemoveAttachment,
        handleUploadImage,
    };
};