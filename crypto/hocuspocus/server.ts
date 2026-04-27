import { Server } from '@hocuspocus/server';
import { Database } from '@hocuspocus/extension-database';
import { Logger } from '@hocuspocus/extension-logger';

const PORT = Number(process.env.HOCUSPOCUS_PORT ?? 1234);
const BACKEND_INTERNAL_URL = (
  process.env.BACKEND_INTERNAL_URL ?? 'http://backend:8000'
).replace(/\/$/, '');
const INTERNAL_SECRET = process.env.HOCUSPOCUS_INTERNAL_SECRET ?? '';
const MAX_UPDATE_BYTES = Number(
  process.env.YJS_MAX_UPDATE_BYTES ?? 1024 * 1024,
);
const REQUEST_TIMEOUT_MS = Number(
  process.env.HOCUSPOCUS_REQUEST_TIMEOUT_MS ?? 5000,
);

if (!INTERNAL_SECRET) {
  console.error(
    '[hocuspocus] FATAL: HOCUSPOCUS_INTERNAL_SECRET is empty. ' +
    'Refusing to start — set the secret in .env before deploying.',
  );
  process.exit(1);
}

const internalHeaders = (extra: Record<string, string> = {}) => ({
  'X-Internal-Token': INTERNAL_SECRET,
  ...extra,
});

function noteIdFromDocumentName(documentName: string): string {
  return documentName.startsWith('note:')
    ? documentName.slice('note:'.length)
    : documentName;
}

async function fetchWithTimeout(
  url: string,
  init: RequestInit,
): Promise<Response> {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), REQUEST_TIMEOUT_MS);
  try {
    return await fetch(url, { ...init, signal: ctrl.signal });
  } finally {
    clearTimeout(timer);
  }
}

const server = Server.configure({
  port: PORT,
  name: 'knovya-hocuspocus',

  async onAuthenticate({ token, documentName, requestParameters }) {
    const noteId = noteIdFromDocumentName(documentName);
    const effectiveToken = token || requestParameters.get('token') || '';
    if (!effectiveToken) {
      throw new Error('Missing token');
    }

    const r = await fetchWithTimeout(
      `${BACKEND_INTERNAL_URL}/api/v1/internal/yjs/validate`,
      {
        method: 'POST',
        headers: internalHeaders({ 'Content-Type': 'application/json' }),
        body: JSON.stringify({ token: effectiveToken, note_id: noteId }),
      },
    );
    if (!r.ok) {
      console.warn(
        `[hocuspocus] auth rejected note=${noteId} status=${r.status}`,
      );
      throw new Error(`Unauthorized (${r.status})`);
    }
    const data = (await r.json()) as {
      user_id: string;
      workspace_id: number;
      permission: string;
      is_encrypted: boolean;
    };
    return {
      userId: data.user_id,
      workspaceId: data.workspace_id,
      permission: data.permission,
      isEncrypted: Boolean(data.is_encrypted),
    };
  },

  extensions: [
    new Database({
      fetch: async ({ documentName }) => {
        const noteId = noteIdFromDocumentName(documentName);
        const r = await fetchWithTimeout(
          `${BACKEND_INTERNAL_URL}/api/v1/internal/yjs/load/${noteId}`,
          { headers: internalHeaders() },
        );
        if (r.status === 204) return null;
        if (!r.ok) {
          console.warn(
            `[hocuspocus] load failed note=${noteId} status=${r.status}`,
          );
          return null;
        }
        const buf = await r.arrayBuffer();
        return new Uint8Array(buf);
      },

      store: async ({ documentName, state, context }) => {
        if (context?.isEncrypted) {
          console.log(
            `[hocuspocus] store skipped (encrypted) note=${
              noteIdFromDocumentName(documentName)
            }`,
          );
          return;
        }
        const noteId = noteIdFromDocumentName(documentName);
        const r = await fetchWithTimeout(
          `${BACKEND_INTERNAL_URL}/api/v1/internal/yjs/save/${noteId}`,
          {
            method: 'POST',
            headers: internalHeaders({
              'Content-Type': 'application/octet-stream',
            }),
            body: state,
          },
        );
        if (!r.ok) {
          console.warn(
            `[hocuspocus] save failed note=${noteId} status=${r.status}`,
          );
          throw new Error(`Save failed (${r.status})`);
        }
      },
    }),
    new Logger({
      onLoadDocument: false,
      onStoreDocument: false,
      onChange: false,
      onConnect: true,
      onDisconnect: true,
      onUpgrade: false,
      onRequest: false,
      onListen: true,
      onDestroy: true,
      onConfigure: true,
    }),
  ],

  async onLoadDocument({ document, documentName, context }) {
    if (context?.isEncrypted) return document;
    const fragment = document.getXmlFragment('document-store');
    if (fragment.length > 0) return document;

    const noteId = noteIdFromDocumentName(documentName);
    try {
      const r = await fetchWithTimeout(
        `${BACKEND_INTERNAL_URL}/api/v1/internal/yjs/initial/${noteId}`,
        { headers: internalHeaders() },
      );
      if (!r.ok) return document;
      const data = (await r.json()) as {
        content_json: unknown[];
        is_encrypted: boolean;
      };
      if (data.is_encrypted) return document;
      console.log(
        `[hocuspocus] initial bootstrap deferred to client ` +
        `note=${noteId} blocks=${
          Array.isArray(data.content_json) ? data.content_json.length : 0
        }`,
      );
    } catch (err) {
      console.warn(
        `[hocuspocus] initial bootstrap failed note=${noteId}:`,
        err,
      );
    }
    return document;
  },

  async beforeHandleMessage(payload) {
    const { documentName, update, socketId } = payload as {
      documentName: string;
      update: Uint8Array;
      socketId: string;
    };

    if (update.byteLength > MAX_UPDATE_BYTES) {
      console.warn(
        `[hocuspocus] rejecting oversized update doc=${documentName} ` +
        `size=${update.byteLength}B (cap ${MAX_UPDATE_BYTES}B)`,
      );
      throw new Error('Update too large');
    }

    const clientId = socketId;
    if (typeof clientId !== 'string' || clientId.length === 0) return;

    try {
      const r = await fetchWithTimeout(
        `${BACKEND_INTERNAL_URL}/api/v1/internal/yjs/rate-check`,
        {
          method: 'POST',
          headers: internalHeaders({ 'Content-Type': 'application/json' }),
          body: JSON.stringify({ client_id: clientId }),
        },
      );
      if (!r.ok) return;
      const data = (await r.json()) as { allowed: boolean };
      if (!data.allowed) {
        console.warn(
          `[hocuspocus] rate-limited client=${clientId} doc=${documentName}`,
        );
        throw new Error('Rate limit exceeded');
      }
    } catch (err) {
      if (err instanceof Error && err.message === 'Rate limit exceeded') {
        throw err;
      }
      console.warn(
        `[hocuspocus] rate-check backend error doc=${documentName}:`,
        err,
      );
    }
  },
});

server
  .listen()
  .then(() => {
    console.log(
      `[hocuspocus] listening on :${PORT} ` +
      `backend=${BACKEND_INTERNAL_URL} max_update=${MAX_UPDATE_BYTES}B`,
    );
  })
  .catch((err) => {
    console.error('[hocuspocus] failed to start:', err);
    process.exit(1);
  });
