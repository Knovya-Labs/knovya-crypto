

import { create } from 'zustand'
import {
  deriveKEK,
  reimportAsNonExtractable,
  unwrapDEK,
} from '@/lib/cryptoUtils'
import type { NoteEncryptionMetadata } from '@/types/notes.types'
import type { EncryptionSetup } from '@/services/settings.service'

const MAX_DEK_CACHE_SIZE = 500

function fromBase64(b64: string): Uint8Array {
  const binary = atob(b64)
  const bytes = new Uint8Array(binary.length)
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i)
  return bytes
}

interface EncryptionState {
  kek: CryptoKey | null
  kekSalt: string | null
  isUnlocked: boolean
  hasSetup: boolean
  _dekCache: Map<string, CryptoKey>
}

interface EncryptionActions {
  unlock: (password: string, setup: EncryptionSetup) => Promise<void>
  lock: () => void
  setHasSetup: (v: boolean) => void
  getDEK: (noteId: string, metadata: NoteEncryptionMetadata) => Promise<CryptoKey>
  setDEK: (noteId: string, dek: CryptoKey) => void
  clearAll: () => void
}

export const useEncryptionStore = create<EncryptionState & EncryptionActions>()(
  (set, get) => ({
    kek: null,
    kekSalt: null,
    isUnlocked: false,
    hasSetup: false,
    _dekCache: new Map(),

    unlock: async (password, setup) => {


      const salt = fromBase64(setup.salt)
      const kek = await deriveKEK(password, salt)


      try {
        await unwrapDEK(kek, setup.wrappedDek, setup.dekIv)
      } catch {
        throw new Error('Wrong password')
      }

      set({
        kek,
        kekSalt: setup.salt,
        isUnlocked: true,
        hasSetup: true,
        _dekCache: new Map(get()._dekCache),
      })
    },

    lock: () => {
      set({
        kek: null,
        kekSalt: null,
        isUnlocked: false,
        _dekCache: new Map(),
      })
    },

    setHasSetup: (v) => set({ hasSetup: v }),

    getDEK: async (noteId, metadata) => {
      const cached = get()._dekCache.get(noteId)
      if (cached) return cached

      const { kek } = get()
      if (!kek) throw new Error('Encryption not unlocked')

      const dek = await unwrapDEK(kek, metadata.wrappedDek, metadata.dekIv)
      const newCache = new Map(get()._dekCache)
      if (newCache.size >= MAX_DEK_CACHE_SIZE) {
        const oldest = newCache.keys().next().value!
        newCache.delete(oldest)
      }
      newCache.set(noteId, dek)
      set({ _dekCache: newCache })
      return dek
    },

    setDEK: (noteId, dek) => {


      const insertSafeDek = (safeDek: CryptoKey) => {
        const newCache = new Map(get()._dekCache)
        if (newCache.size >= MAX_DEK_CACHE_SIZE) {
          const oldest = newCache.keys().next().value!
          newCache.delete(oldest)
        }
        newCache.set(noteId, safeDek)
        set({ _dekCache: newCache })
      }
      if (!dek.extractable) {


        insertSafeDek(dek)
        return
      }


      void (async () => {
        const safeDek = await reimportAsNonExtractable(dek)
        insertSafeDek(safeDek)
      })()
    },

    clearAll: () => {
      set({
        kek: null,
        kekSalt: null,
        isUnlocked: false,
        _dekCache: new Map(),
      })
    },
  }),
)

if (typeof window !== 'undefined') {
  window.addEventListener('beforeunload', () => {
    useEncryptionStore.getState().clearAll()
  })

  const IDLE_TIMEOUT_MS = 30 * 60 * 1000
  let idleTimer: ReturnType<typeof setTimeout> | null = null

  function resetIdleTimer() {
    if (idleTimer) clearTimeout(idleTimer)
    if (!useEncryptionStore.getState().isUnlocked) return
    idleTimer = setTimeout(() => {
      window.dispatchEvent(new CustomEvent('knovya:encryption-idle-lock'))
      setTimeout(() => useEncryptionStore.getState().lock(), 100)
    }, IDLE_TIMEOUT_MS)
  }

  for (const evt of ['mousemove', 'keydown', 'scroll', 'click', 'touchstart']) {
    document.addEventListener(evt, resetIdleTimer, { passive: true })
  }

  useEncryptionStore.subscribe((state, prev) => {
    if (state.isUnlocked && !prev.isUnlocked) resetIdleTimer()
    if (!state.isUnlocked && idleTimer) { clearTimeout(idleTimer); idleTimer = null }
  })
}
