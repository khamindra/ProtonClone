import { useEffect, ChangeEvent, Ref, memo, forwardRef, MutableRefObject, useContext } from 'react';
import { c, msgid } from 'ttag';
import {
    useLabels,
    classnames,
    MnemonicPromptModal,
    PaginationRow,
    useItemsDraggable,
    EllipsisLoader,
    useModals,
    useIsMnemonicAvailable,
    useSettingsLink,
} from '@proton/components';
import { GetStartedChecklistKey, MailSettings, UserSettings } from '@proton/shared/lib/interfaces';
import { DENSITY } from '@proton/shared/lib/constants';

import Item from './Item';
import { Element } from '../../models/element';
import EmptyView from '../view/EmptyView';
import { isMessage as testIsMessage } from '../../helpers/elements';
import { usePlaceholders } from '../../hooks/usePlaceholders';
import { Breakpoints } from '../../models/utils';
import { Sort, Filter } from '../../models/tools';
import { usePaging } from '../../hooks/usePaging';
import ListSettings from './ListSettings';
import ESSlowToolbar from './ESSlowToolbar';
import { useEncryptedSearchContext } from '../../containers/EncryptedSearchProvider';
import useEncryptedSearchList from './useEncryptedSearchList';
import GetStartedChecklist from '../checklist/GetStartedChecklist';
import { isColumnMode } from '../../helpers/mailSettings';
import { MESSAGE_ACTIONS } from '../../constants';
import { useOnCompose } from '../../containers/ComposeProvider';
import { GetStartedChecklistContext } from '../../containers/GetStartedChecklistProvider';
import ModalImportEmails from '../checklist/ModalImportEmails';
import ModalGetMobileApp from '../checklist/ModalGetMobileApp';

const defaultCheckedIDs: string[] = [];
const defaultElements: Element[] = [];

interface Props {
    labelID: string;
    loading: boolean;
    placeholderCount: number;
    elementID?: string;
    userSettings: UserSettings;
    mailSettings: MailSettings;
    columnLayout: boolean;
    elements?: Element[];
    checkedIDs?: string[];
    onCheck: (ID: string[], checked: boolean, replace: boolean) => void;
    onCheckOne: (event: ChangeEvent, ID: string) => void;
    onClick: (elementID: string | undefined) => void;
    onFocus: (number: number) => void;
    conversationMode: boolean;
    isSearch: boolean;
    breakpoints: Breakpoints;
    page: number;
    total: number | undefined;
    onPage: (page: number) => void;
    sort: Sort;
    onSort: (sort: Sort) => void;
    filter: Filter;
    onFilter: (filter: Filter) => void;
}

const List = (
    {
        labelID,
        loading,
        placeholderCount,
        elementID,
        userSettings,
        mailSettings,
        columnLayout,
        elements: inputElements = defaultElements,
        checkedIDs = defaultCheckedIDs,
        onCheck,
        onClick,
        conversationMode,
        isSearch,
        breakpoints,
        page: inputPage,
        total: inputTotal,
        onPage,
        onFocus,
        onCheckOne,
        sort,
        onSort,
        filter,
        onFilter,
    }: Props,
    ref: Ref<HTMLDivElement>
) => {
    const [labels] = useLabels();
    const { shouldHighlight } = useEncryptedSearchContext();
    // Override compactness of the list view to accomodate body preview when showing encrypted search results
    const isCompactView = userSettings.Density === DENSITY.COMPACT && !shouldHighlight();

    const onCompose = useOnCompose();
    const { createModal } = useModals();
    const isMnemonicAvailable = useIsMnemonicAvailable();
    const goToSettings = useSettingsLink();
    const elements = usePlaceholders(inputElements, loading, placeholderCount);
    const { dismissed: getStartedDismissed, handleDismiss } = useContext(GetStartedChecklistContext);
    const pagingHandlers = usePaging(inputPage, inputTotal, onPage);
    const { page, total } = pagingHandlers;

    // Scroll top when changing page
    useEffect(() => {
        (ref as MutableRefObject<HTMLElement | null>).current?.scroll?.({ top: 0 });
    }, [loading, page]);

    // ES options: offer users the option to turn off ES if it's taking too long, and
    // enable/disable UI elements for incremental partial searches
    const { showESSlowToolbar, loadingElement, disableGoToLast, useLoadingElement } = useEncryptedSearchList(
        isSearch,
        loading,
        page,
        total
    );

    const { draggedIDs, handleDragStart, handleDragEnd } = useItemsDraggable(
        elements,
        checkedIDs,
        onCheck,
        (draggedIDs) => {
            const isMessage = elements.length && testIsMessage(elements[0]);
            const selectionCount = draggedIDs.length;
            return isMessage
                ? c('Success').ngettext(
                      msgid`Move ${selectionCount} message`,
                      `Move ${selectionCount} messages`,
                      selectionCount
                  )
                : c('Success').ngettext(
                      msgid`Move ${selectionCount} conversation`,
                      `Move ${selectionCount} conversations`,
                      selectionCount
                  );
        }
    );

    return (
        <div
            ref={ref}
            className={classnames([
                'items-column-list scroll-if-needed scroll-smooth-touch',
                isCompactView && 'list-compact',
            ])}
        >
            <h1 className="sr-only">
                {conversationMode ? c('Title').t`Conversation list` : c('Title').t`Message list`}
            </h1>
            <div className="items-column-list-inner flex flex-nowrap flex-column relative">
                <ListSettings
                    sort={sort}
                    onSort={onSort}
                    onFilter={onFilter}
                    filter={filter}
                    conversationMode={conversationMode}
                    mailSettings={mailSettings}
                    isSearch={isSearch}
                    labelID={labelID}
                />
                {showESSlowToolbar && <ESSlowToolbar />}
                {elements.length === 0 ? (
                    <EmptyView labelID={labelID} isSearch={isSearch} />
                ) : (
                    <>
                        {elements.map((element, index) => (
                            <Item
                                key={element.ID}
                                conversationMode={conversationMode}
                                labels={labels}
                                labelID={labelID}
                                loading={loading}
                                columnLayout={columnLayout}
                                elementID={elementID}
                                element={element}
                                checked={checkedIDs.includes(element.ID || '')}
                                onCheck={onCheckOne}
                                onClick={onClick}
                                mailSettings={mailSettings}
                                onDragStart={handleDragStart}
                                onDragEnd={handleDragEnd}
                                dragged={draggedIDs.includes(element.ID || '')}
                                index={index}
                                breakpoints={breakpoints}
                                onFocus={onFocus}
                            />
                        ))}

                        {userSettings.Checklists?.includes('get-started') &&
                            !loading &&
                            !(total > 1) &&
                            !getStartedDismissed && (
                                <GetStartedChecklist
                                    limitedMaxWidth={!isColumnMode(mailSettings)}
                                    onDismiss={handleDismiss}
                                    onItemSelection={(key: GetStartedChecklistKey) => () => {
                                        /* eslint-disable default-case */
                                        switch (key) {
                                            case GetStartedChecklistKey.SendMessage: {
                                                onCompose({ action: MESSAGE_ACTIONS.NEW });
                                                break;
                                            }

                                            case GetStartedChecklistKey.MobileApp: {
                                                createModal(<ModalGetMobileApp />);
                                                break;
                                            }

                                            case GetStartedChecklistKey.RecoveryMethod: {
                                                if (isMnemonicAvailable) {
                                                    createModal(<MnemonicPromptModal />);
                                                } else {
                                                    goToSettings('/authentication#recovery-notification', undefined, true);
                                                }
                                                break;
                                            }

                                            case GetStartedChecklistKey.Import: {
                                                createModal(<ModalImportEmails />);
                                                break;
                                            }
                                        }
                                    }}
                                />
                            )}

                        {useLoadingElement && loadingElement}

                        {!loading && total > 1 && (
                            <div className="p1-5 flex flex-column flex-align-items-center">
                                <PaginationRow
                                    {...pagingHandlers}
                                    disabled={loading}
                                    disableGoToLast={disableGoToLast}
                                />
                            </div>
                        )}
                    </>
                )}
            </div>
        </div>
    );
};

export default memo(forwardRef(List));
