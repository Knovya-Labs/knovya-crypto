

import { useEffect, useMemo, useRef, useState } from 'react';
import * as Y from 'yjs';
import { HocuspocusProvider, WebSocketStatus } from '@hocuspocus/provider';
import { IndexeddbPersistence } from 'y-indexeddb';

import { onSocketReconnect } from '@/lib/socket';
import { setLocalAwareness } from './yjsAwareness';

export type YjsConnectionStatus =
  | 'idle'
  | 'connecting'
  | 'connected'
  | 'disconnected';

export interface YjsDocHandle {
  doc: Y.Doc;
  provider: HocuspocusProvider;
  awareness: HocuspocusProvider['awareness'];
  status: YjsConnectionStatus;

  hasOfflinePersistence: boolean;

  synced: boolean;

  idbSynced: boolean;
}

export interface UseYjsDocArgs {

  noteId: string | null | undefined;

  isEncrypted: boolean;

  crdtYjsEnabled: boolean;

  getToken?: () => string | null;

  wsUrl?: string;

  user: {
    id: string;
    name: string;
    color: string;
  };
}

const DEFAULT_FRAGMENT_NAME = 'document-store';

function defaultGetToken(): string | null {
  if (typeof window === 'undefined') return null;
  try {
    return window.localStorage.getItem('access_token');
  } catch {
    return null;
  }
}

function deriveWsUrl(): string {
  if (typeof window === 'undefined') return '';
  const apiUrl = (import.meta as unknown as { env?: Record<string, string> })
    .env?.VITE_API_URL;
  const base = apiUrl
    ? new URL(apiUrl).origin
    : window.location.origin;


  return `${base.replace(/^http/, 'ws')}/yjs/`;
}

export function useYjsDoc(args: UseYjsDocArgs): YjsDocHandle | null {
  const {
    noteId,
    isEncrypted,
    crdtYjsEnabled,
    getToken = defaultGetToken,
    wsUrl,
    user,
  } = args;

  const [status, setStatus] = useState<YjsConnectionStatus>('idle');


  const [synced, setSynced] = useState(false);
  const [idbSynced, setIdbSynced] = useState(false);


  const getTokenRef = useRef(getToken);
  getTokenRef.current = getToken;
  const wsUrlRef = useRef(wsUrl);
  wsUrlRef.current = wsUrl;


  const refs = useMemo(() => {
    if (!crdtYjsEnabled) return null;
    if (!noteId) return null;
    if (typeof window === 'undefined') return null;


    if (isEncrypted) return null;

    const doc = new Y.Doc();


    const idbProvider: IndexeddbPersistence | null = new IndexeddbPersistence(
      `yjs:note:${noteId}`,
      doc,
    );


    const url = wsUrlRef.current ?? deriveWsUrl();
    const provider = new HocuspocusProvider({
      url,
      name: `note:${noteId}`,
      document: doc,


      token: getTokenRef.current() ?? '',
      connect: true,


      delay: 1_000,
      factor: 2,
      maxAttempts: 0,


      messageReconnectTimeout: 30_000,


      onAuthenticationFailed: ({ reason }) => {
        try {


          if (reason && reason !== 'permission-denied') {

            console.warn('[useYjsDoc] auth failed:', reason);
          }
          provider.disconnect();
        } catch {

        }
      },
    });

    return { doc, provider, idbProvider };


  }, [crdtYjsEnabled, noteId, isEncrypted]);


  useEffect(() => {
    if (!refs) {
      setStatus('idle');
      setSynced(false);
      setIdbSynced(false);
      return;
    }
    setStatus('connecting');


    setSynced(
      Boolean((refs.provider as unknown as { synced?: boolean }).synced),
    );
    setIdbSynced(refs.idbProvider == null);


    const onStatus = ({ status: next }: { status: WebSocketStatus }) => {
      if (next === WebSocketStatus.Connected) setStatus('connected');
      else if (next === WebSocketStatus.Connecting) setStatus('connecting');
      else setStatus('disconnected');
    };
    refs.provider.on('status', onStatus);


    const onSynced = () => setSynced(true);
    refs.provider.on('synced', onSynced);


    let idbWhenSyncedCancelled = false;
    if (refs.idbProvider) {
      const onIdbSynced = () => setIdbSynced(true);
      refs.idbProvider.on('synced', onIdbSynced);


      Promise.resolve(refs.idbProvider.whenSynced)
        .then(() => {
          if (!idbWhenSyncedCancelled) setIdbSynced(true);
        })
        .catch(() => {

          if (!idbWhenSyncedCancelled) setIdbSynced(true);
        });
    }


    const unsubscribe = onSocketReconnect(() => {
      try {
        refs.provider.disconnect();
        refs.provider.connect();
      } catch {

      }
    });

    return () => {
      refs.provider.off('status', onStatus);
      refs.provider.off('synced', onSynced);
      idbWhenSyncedCancelled = true;
      unsubscribe();
    };
  }, [refs]);


  useEffect(() => {
    if (!refs) return;
    setLocalAwareness(refs.provider.awareness, {
      user,
      cursor: null,
      agentName: 'human',
    });
  }, [refs, user]);


  useEffect(() => {
    if (!refs) return;
    return () => {
      try {


        refs.provider.awareness.setLocalState(null);
      } catch {

      }
      try {
        refs.provider.disconnect();
      } catch {

      }
      try {
        refs.provider.destroy();
      } catch {

      }
      try {
        refs.idbProvider?.destroy();
      } catch {

      }
      try {
        refs.doc.destroy();
      } catch {

      }
    };
  }, [refs]);

  if (!refs) return null;

  return {
    doc: refs.doc,
    provider: refs.provider,
    awareness: refs.provider.awareness,
    status,
    hasOfflinePersistence: refs.idbProvider != null,
    synced,
    idbSynced,
  };
}
