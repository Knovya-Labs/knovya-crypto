import { useCallback, useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { useQueryClient } from '@tanstack/react-query'

import type { KnovyaTokens } from '@/styles/knovya-tokens'
import {
  buildEncryptionSetup,
  changeEncryptionPassword,
  deriveKEK,
  deriveKEKFromMetadata,
  generateSalt,
} from '@/lib/cryptoUtils'
import type { EncryptionMetadata } from '@/lib/cryptoUtils'
import { queryKeys } from '@/lib/queryKeys'
import { encryptionChangePasswordService } from '@/services/encryption-change-password.service'
import { notesService } from '@/services/notes.service'
import { useEncryptionStore } from '@/store/encryptionStore'

import { useEncryptionChangePassword } from '../hooks/useEncryptionChangePassword'

import { EncryptionCommitStep } from './EncryptionCommitStep'
import { EncryptionDryRunStep } from './EncryptionDryRunStep'
import { EncryptionStartStep } from './EncryptionStartStep'

interface Props {
  t: KnovyaTokens
  onClose: () => void
  resumeRotationId?: string | null
}

interface RotationContext {
  oldKek: CryptoKey
  newPassword: string
  encryptedNotes: Array<{
    id: string
    version: number
    encryption_metadata: EncryptionMetadata
  }>
}

interface DryRunResult {
  testedCount: number
  succeededCount: number
  errors: string[]
  canProceed: boolean
}

interface CommitResult {
  notesTotal: number
  notesReEncrypted: number
  notesFailed: number
  startedAt: number
}

const SAMPLE_SIZE = 10


const ENCRYPTED_NOTES_PAGE_SIZE = 100


const BATCH_REENCRYPT_CHUNK_SIZE = 100


export function EncryptionChangePasswordWizard({
  t,
  onClose,
}: Props) {
  const { t: tp } = useTranslation('settings')
  const queryClient = useQueryClient()
  const isUnlocked = useEncryptionStore((s) => s.isUnlocked)
  const cachedKek = useEncryptionStore((s) => s.kek)
  const wizard = useEncryptionChangePassword()

  const [rotationContext, setRotationContext] = useState<RotationContext | null>(null)
  const [dryRunResult, setDryRunResult] = useState<DryRunResult | null>(null)
  const [commitResult, setCommitResult] = useState<CommitResult | null>(null)


  useEffect(() => () => wizard.reset(), [wizard])


  const fetchEncryptedNotes = useCallback(async () => {
    const all: RotationContext['encryptedNotes'] = []
    let offset = 0
    while (true) {
      const resp = await notesService.getNotes({
        status: 'active',
        encrypted: true,
        limit: ENCRYPTED_NOTES_PAGE_SIZE,
        offset,
      })
      const items = resp.items ?? []
      for (const n of items) {
        if (n.is_encrypted && n.encryption_metadata) {
          all.push({
            id: n.id,
            version: n.version,
            encryption_metadata: n.encryption_metadata as EncryptionMetadata,
          })
        }
      }
      if (items.length < ENCRYPTED_NOTES_PAGE_SIZE) break
      offset += ENCRYPTED_NOTES_PAGE_SIZE
    }
    return all
  }, [])

  const handleStart = useCallback(
    async ({
      oldPassword,
      newPassword,
      backupAcknowledged,
    }: {
      oldPassword: string
      newPassword: string
      backupAcknowledged: boolean
    }) => {
      try {
        const encryptedNotes = await fetchEncryptedNotes()


        let oldKek = cachedKek
        if (!oldKek) {
          if (encryptedNotes.length === 0) {
            throw new Error(tp('encryption.changePassword.errors.noNotes'))
          }
          oldKek = await deriveKEKFromMetadata(
            oldPassword,
            encryptedNotes[0].encryption_metadata,
          )
        }


        const startResp = await wizard.start({
          backup_key_acknowledged: backupAcknowledged,
          new_kek_version: 2,
        })
        if (!startResp) {

          return
        }

        setRotationContext({
          oldKek,
          newPassword,
          encryptedNotes,
        })


        await runDryRun(oldKek, newPassword, encryptedNotes)
      } catch (err) {
        console.error('Encryption rotation start failed', err)
      }
    },
    [cachedKek, fetchEncryptedNotes, tp, wizard],
  )

  const runDryRun = useCallback(
    async (
      oldKek: CryptoKey,
      newPassword: string,
      encryptedNotes: RotationContext['encryptedNotes'],
    ) => {
      const sample = encryptedNotes.slice(0, SAMPLE_SIZE)
      const errors: string[] = []
      let succeeded = 0

      try {


        const sampleKek = await deriveKEK(newPassword, generateSalt())
        for (const note of sample) {
          try {
            await changeEncryptionPassword(oldKek, newPassword, [
              { noteId: note.id, metadata: note.encryption_metadata },
            ])
            succeeded += 1
          } catch (err) {
            errors.push(
              `Note ${note.id.slice(0, 8)}: ${
                err instanceof Error ? err.message.slice(0, 100) : 'unknown'
              }`,
            )
          }
        }


        void sampleKek
      } catch (err) {
        errors.push(
          err instanceof Error ? err.message : 'Dry-run preparation failed',
        )
      }

      const result: DryRunResult = {
        testedCount: sample.length,
        succeededCount: succeeded,
        errors,
        canProceed: sample.length > 0 && succeeded === sample.length,
      }

      setDryRunResult(result)


      await wizard.dryRun({
        sample_notes_tested: result.testedCount,
        sample_notes_succeeded: result.succeededCount,
        errors: result.errors,
      })
    },
    [wizard],
  )


  const commitChunkWithReconcile = useCallback(
    async (
      rotationId: string,
      expectedNewSalt: string,
      chunkItems: Array<{
        note_id: string
        encryption_metadata: EncryptionMetadata
        version: number
      }>,
    ): Promise<{ succeeded: number; failed: number }> => {
      try {
        const resp = await notesService.batchReencrypt(chunkItems)
        return {
          succeeded: resp.updated_count,
          failed: chunkItems.length - resp.updated_count,
        }
      } catch (err) {
        let reconcile
        try {
          reconcile = await encryptionChangePasswordService.reconcileBatch({
            rotation_id: rotationId,
            expected_new_salt: expectedNewSalt,
            note_ids: chunkItems.map((it) => it.note_id),
          })
        } catch (reconcileErr) {
          console.error('reconcile-batch failed', reconcileErr)
          return { succeeded: 0, failed: chunkItems.length }
        }

        if (reconcile.pending.length === 0) {


          return {
            succeeded: reconcile.already_done.length,
            failed: 0,
          }
        }

        if (reconcile.already_done.length === 0) {


          try {
            const retryResp = await notesService.batchReencrypt(chunkItems)
            return {
              succeeded: retryResp.updated_count,
              failed: chunkItems.length - retryResp.updated_count,
            }
          } catch (retryErr) {
            console.error('reconcile retry batchReencrypt failed', retryErr)
            return { succeeded: 0, failed: chunkItems.length }
          }
        }


        console.error(
          'reconcile reported mixed state — atomic batch contract violated',
          reconcile,
        )
        return {
          succeeded: reconcile.already_done.length,
          failed: reconcile.pending.length,
        }
      }
    },
    [],
  )

  const handleCommit = useCallback(async () => {
    if (!rotationContext) return
    if (!wizard.state.rotationId) return
    const startedAt = Date.now()
    setCommitResult({
      notesTotal: rotationContext.encryptedNotes.length,
      notesReEncrypted: 0,
      notesFailed: 0,
      startedAt,
    })

    try {
      const { oldKek, newPassword, encryptedNotes } = rotationContext


      const result = await changeEncryptionPassword(
        oldKek,
        newPassword,
        encryptedNotes.map((n) => ({
          noteId: n.id,
          metadata: n.encryption_metadata,
        })),
      )


      const allItems = result.updates.map((upd) => {
        const original = encryptedNotes.find((n) => n.id === upd.noteId)
        return {
          note_id: upd.noteId,
          encryption_metadata: upd.metadata,
          version: original?.version ?? 1,
        }
      })


      const newSetup = await buildEncryptionSetup(
        result.newKek,
        result.newSalt,
      )

      const expectedNewSalt = newSetup.salt
      let succeeded = 0
      let failed = 0
      for (let i = 0; i < allItems.length; i += BATCH_REENCRYPT_CHUNK_SIZE) {
        const chunk = allItems.slice(i, i + BATCH_REENCRYPT_CHUNK_SIZE)
        const chunkResult = await commitChunkWithReconcile(
          wizard.state.rotationId,
          expectedNewSalt,
          chunk,
        )
        succeeded += chunkResult.succeeded
        failed += chunkResult.failed


        setCommitResult({
          notesTotal: encryptedNotes.length,
          notesReEncrypted: succeeded,
          notesFailed: failed,
          startedAt,
        })
      }


      useEncryptionStore.setState({
        kek: result.newKek,
        kekSalt: newSetup.salt,
        isUnlocked: true,
        _dekCache: new Map(),
      })


      await wizard.commit({
        notes_total: encryptedNotes.length,
        notes_re_encrypted: succeeded,
        notes_failed: failed,
        duration_seconds: (Date.now() - startedAt) / 1000,
        new_encryption_setup: newSetup,
      })

      setCommitResult({
        notesTotal: encryptedNotes.length,
        notesReEncrypted: succeeded,
        notesFailed: failed,
        startedAt,
      })


      queryClient.invalidateQueries({ queryKey: queryKeys.notes.all })
      queryClient.invalidateQueries({
        queryKey: queryKeys.user.preferences(),
      })
    } catch (err) {
      console.error('Encryption commit failed', err)
    }
  }, [commitChunkWithReconcile, queryClient, rotationContext, wizard])

  const handleCancel = useCallback(async () => {
    await wizard.cancel()
    onClose()
  }, [onClose, wizard])


  if (commitResult || wizard.state.phase === 'committing' || wizard.state.phase === 'completed') {
    return (
      <EncryptionCommitStep
        t={t}
        isRunning={wizard.state.phase === 'committing'}
        isCompleted={wizard.state.phase === 'completed'}
        notesTotal={commitResult?.notesTotal ?? 0}
        notesReEncrypted={commitResult?.notesReEncrypted ?? 0}
        notesFailed={commitResult?.notesFailed ?? 0}
        onClose={onClose}
      />
    )
  }


  if (
    dryRunResult
    || wizard.state.phase === 'dry-running'
    || wizard.state.phase === 'dry-run-complete'
  ) {
    return (
      <EncryptionDryRunStep
        t={t}
        isRunning={wizard.state.phase === 'dry-running'}
        testedCount={dryRunResult?.testedCount ?? 0}
        succeededCount={dryRunResult?.succeededCount ?? 0}
        errors={dryRunResult?.errors ?? []}
        canProceed={dryRunResult?.canProceed ?? false}
        onProceed={handleCommit}
        onCancel={handleCancel}
      />
    )
  }


  return (
    <EncryptionStartStep
      t={t}
      isUnlocked={isUnlocked}
      onSubmit={handleStart}
      onCancel={handleCancel}
      isSubmitting={
        wizard.state.phase === 'starting'
        || wizard.state.phase === 'dry-running'
      }
      errorMessage={wizard.state.errorMessage}
    />
  )
}
