<!--
  The printers waiting to be admitted, in the two tiers a listing has here.

  The switch is a container query and not a measurement in script, the same way
  the printers listing does it: both tiers stay in the DOM and the one that
  does not apply is `display: none`. 66rem is where the five columns stop
  fitting, and the test beside this file re-measures that floor so a sixth
  column cannot push the table past it in silence.

  The reject question lives here rather than on the screen, because the button
  that asks it is in this file and a dialog held two files away is a dialog
  somebody wires to the wrong row.
-->
<script lang="ts">
  import CheckIcon from '@lucide/svelte/icons/check';
  import XIcon from '@lucide/svelte/icons/x';

  import { t } from '../../i18n';
  import {
    Button,
    ConfirmDialog,
    DataRow,
    RowList,
    Table,
    TableBody,
    TableCaption,
    TableCell,
    TableHead,
    TableHeader,
    TableRow,
    type DataRowValue,
  } from '../../primitives';
  import { printerModelLabelOf } from '../printers/presentation';
  import { formatFingerprint } from './presentation';
  import type { PendingPrinter } from './types';

  let {
    pending,
    onApprove,
    onReject,
  }: {
    pending: readonly PendingPrinter[];
    onApprove: (code: string) => void;
    onReject: (code: string) => void;
  } = $props();

  // The code and the fingerprint are the two values the card's own instruction
  // asks a person to check against the printer's display. Both are drawn at
  // this heavier weight so the pair reads as one thing to compare; the model,
  // the firmware and the serial only help recognise which physical printer is
  // asking, so they stay at the row's ordinary weight.
  const COMPARE =
    'font-mono text-base font-semibold text-foreground tabular-nums';

  let rejecting = $state<PendingPrinter | null>(null);

  const nameOf = (entry: PendingPrinter): string =>
    entry.model === undefined
      ? t('addPrinter.unknownModel')
      : printerModelLabelOf(entry.model);

  const secondaries = (
    entry: PendingPrinter,
    pair: DataRowValue,
  ): DataRowValue[] => [
    pair,
    entry.firmware !== undefined &&
      t('addPrinter.row.firmware', { version: entry.firmware }),
    entry.serial,
  ];
</script>

<div class="@container/pending-approvals">
  <div class="hidden @[66rem]/pending-approvals:block">
    <Table>
      <TableCaption class="sr-only">
        {t('addPrinter.waiting.caption')}
      </TableCaption>
      <TableHeader>
        <TableRow>
          <TableHead>{t('addPrinter.columns.printer')}</TableHead>
          <TableHead>{t('addPrinter.columns.code')}</TableHead>
          <TableHead>{t('addPrinter.columns.fingerprint')}</TableHead>
          <TableHead>{t('addPrinter.columns.firmware')}</TableHead>
          <TableHead class="sr-only">
            {t('addPrinter.columns.actions')}
          </TableHead>
        </TableRow>
      </TableHeader>
      <TableBody>
        {#each pending as entry (entry.code)}
          <TableRow>
            <TableCell>
              <span class="text-sm font-medium text-foreground">
                {nameOf(entry)}
              </span>
            </TableCell>
            <TableCell class="whitespace-nowrap">
              <span class={COMPARE}>{entry.code}</span>
            </TableCell>
            <TableCell class="whitespace-nowrap">
              <span class={COMPARE}>{formatFingerprint(entry.fingerprint)}</span
              >
            </TableCell>
            <!-- Firmware and serial share one column, stacked. Neither is the
                 security check, so neither needs an aligned column of its own,
                 and the serial truncates with the whole value in `title`
                 rather than setting the table's own min-content width. -->
            <TableCell class="max-w-40">
              <div class="flex flex-col text-xs text-muted-foreground">
                <span>{entry.firmware ?? ''}</span>
                <span
                  class="truncate font-mono tabular-nums"
                  title={entry.serial}>{entry.serial ?? ''}</span
                >
              </div>
            </TableCell>
            <TableCell>
              <!-- `lg`, not the row's usual `sm`: admitting an unknown printer
                   onto the network is a higher-stakes press than an ordinary
                   row action. -->
              <div class="flex items-center gap-2">
                <Button
                  size="lg"
                  aria-label={t('addPrinter.approveFor', {
                    printer: nameOf(entry),
                    code: entry.code,
                  })}
                  onclick={() => {
                    onApprove(entry.code);
                  }}
                >
                  <CheckIcon aria-hidden="true" />
                  {t('addPrinter.approve')}
                </Button>
                <Button
                  variant="destructive"
                  size="lg"
                  aria-label={t('addPrinter.rejectFor', {
                    printer: nameOf(entry),
                    code: entry.code,
                  })}
                  onclick={() => {
                    rejecting = entry;
                  }}
                >
                  <XIcon aria-hidden="true" />
                  {t('addPrinter.reject')}
                </Button>
              </div>
            </TableCell>
          </TableRow>
        {/each}
      </TableBody>
    </Table>
  </div>

  <div class="@[66rem]/pending-approvals:hidden">
    <RowList>
      {#each pending as entry (entry.code)}
        {#snippet comparePair()}
          <span class="inline-flex flex-col items-start gap-0.5">
            <span class={COMPARE}>{formatFingerprint(entry.fingerprint)}</span>
            <span class={COMPARE}>{entry.code}</span>
          </span>
        {/snippet}
        <div class="border-b border-border last:border-b-0">
          <!-- The pair is the row's first value, which is the one `DataRow`
               never shrinks, so neither of the two values a person compares
               loses characters on a narrow screen. `wrapValues` gives the rest
               a line each instead of squeezing them all onto one. -->
          <DataRow
            primary={nameOf(entry)}
            class="border-b-0"
            wrapValues
            secondaryValues={secondaries(entry, comparePair)}
          />
          <!-- Their own row under the facts, not `DataRow`'s inline `actions`
               slot: two 44px buttons beside a row this narrow crowd the code
               and the fingerprint down to a few visible characters. A basis
               rather than two halves, because `Button` carries its own
               `shrink-0`, so they wrap onto two full lines where neither
               fits. -->
          <div class="flex flex-wrap items-center gap-2 px-2 pb-2">
            <Button
              size="lg"
              class="flex-1 basis-32"
              aria-label={t('addPrinter.approveFor', {
                printer: nameOf(entry),
                code: entry.code,
              })}
              onclick={() => {
                onApprove(entry.code);
              }}
            >
              <CheckIcon aria-hidden="true" />
              {t('addPrinter.approve')}
            </Button>
            <Button
              variant="destructive"
              size="lg"
              class="flex-1 basis-32"
              aria-label={t('addPrinter.rejectFor', {
                printer: nameOf(entry),
                code: entry.code,
              })}
              onclick={() => {
                rejecting = entry;
              }}
            >
              <XIcon aria-hidden="true" />
              {t('addPrinter.reject')}
            </Button>
          </div>
        </div>
      {/each}
    </RowList>
  </div>
</div>

<ConfirmDialog
  open={rejecting !== null}
  onOpenChange={(open: boolean) => {
    if (!open) rejecting = null;
  }}
  title={rejecting?.model === undefined
    ? t('addPrinter.reject.unknownTitle')
    : t('addPrinter.reject.title', {
        printer: printerModelLabelOf(rejecting.model),
      })}
  description={t('addPrinter.reject.note')}
  confirmLabel={t('addPrinter.reject')}
  onConfirm={() => {
    if (rejecting !== null) onReject(rejecting.code);
    rejecting = null;
  }}
/>
