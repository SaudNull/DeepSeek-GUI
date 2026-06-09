import type { ReactElement } from 'react'
import {
  Binary,
  FileText,
  GitCompare,
  Network,
  PanelRightClose,
  Radar,
  ShieldAlert,
  Sparkles
} from 'lucide-react'
import { useTranslation } from 'react-i18next'

type Props = {
  className?: string
  onUsePrompt: (prompt: string) => void
  onCollapse: () => void
}

const WORKFLOWS = [
  {
    key: 'triage',
    icon: Binary,
    prompt: 'Triage this binary.',
    labelKey: 'reWorkflowTriage'
  },
  {
    key: 'protection',
    icon: ShieldAlert,
    prompt: 'Analyze protection/obfuscation and build a behavior graph.',
    labelKey: 'reWorkflowProtection'
  },
  {
    key: 'crypto',
    icon: Radar,
    prompt: 'Find crypto routines, string/config decoders, and decode/decrypt stages.',
    labelKey: 'reWorkflowCrypto'
  },
  {
    key: 'iocs',
    icon: Network,
    prompt: 'Extract IOCs and connect them to imports, strings, and likely consumer functions.',
    labelKey: 'reWorkflowIocs'
  },
  {
    key: 'diff',
    icon: GitCompare,
    prompt: 'Compare these two binaries and rank patched or behavior-changing regions.',
    labelKey: 'reWorkflowDiff'
  },
  {
    key: 'report',
    icon: FileText,
    prompt: 'Generate a reverse engineering report.',
    labelKey: 'reWorkflowReport'
  }
]

export function ReModePanel({
  className = '',
  onUsePrompt,
  onCollapse
}: Props): ReactElement {
  const { t } = useTranslation('common')
  return (
    <aside className={`ds-no-drag flex min-h-0 flex-col border-l border-ds-border-muted bg-white backdrop-blur-xl dark:bg-ds-canvas ${className}`}>
      <div className="shrink-0 border-b border-ds-border-muted bg-white/92 dark:bg-ds-card">
        <div className="flex h-12 min-w-0 items-center gap-2 px-4">
          <button
            type="button"
            onClick={onCollapse}
            className="ds-sidebar-toggle-button shrink-0"
            aria-label={t('rightPanelCollapse')}
            title={t('rightPanelCollapse')}
          >
            <PanelRightClose className="h-4 w-4" strokeWidth={1.85} />
          </button>
          <div className="flex min-w-0 flex-1 items-center gap-2 rounded-[12px] bg-ds-surface-subtle px-3 py-1.5 dark:bg-white/8">
            <Binary className="h-4 w-4 shrink-0 text-accent" strokeWidth={1.85} />
            <span className="truncate text-[13px] font-semibold text-ds-ink">
              {t('reverseEngineering')}
            </span>
          </div>
        </div>
      </div>

      <div className="min-h-0 flex-1 overflow-y-auto p-4">
        <div className="grid gap-2">
          {WORKFLOWS.map((workflow) => {
            const Icon = workflow.icon
            return (
              <button
                key={workflow.key}
                type="button"
                onClick={() => onUsePrompt(workflow.prompt)}
                className="group flex min-h-11 w-full min-w-0 items-center gap-3 rounded-[8px] border border-ds-border-muted bg-ds-card px-3 py-2 text-left transition hover:bg-ds-hover"
              >
                <span className="flex h-8 w-8 shrink-0 items-center justify-center rounded-[8px] bg-ds-surface-subtle text-ds-muted group-hover:text-ds-ink">
                  <Icon className="h-4 w-4" strokeWidth={1.85} />
                </span>
                <span className="min-w-0 flex-1 truncate text-[13px] font-semibold text-ds-ink">
                  {t(workflow.labelKey)}
                </span>
              </button>
            )
          })}
        </div>

        <div className="mt-5 rounded-[8px] border border-ds-border-muted bg-ds-card p-3">
          <div className="flex items-center gap-2 text-[12px] font-semibold uppercase tracking-normal text-ds-faint">
            <Sparkles className="h-3.5 w-3.5" strokeWidth={1.9} />
            {t('reArtifactsTitle')}
          </div>
          <div className="mt-3 space-y-1.5 text-[12.5px] font-medium text-ds-muted">
            {['.re-mode/analysis.json', '.re-mode/behavior-graph.json', '.re-mode/iocs.json', '.re-mode/functions/', '.re-mode/raw/ghidra/', '.re-mode/report.md'].map((path) => (
              <div key={path} className="truncate rounded-[6px] bg-ds-surface-subtle px-2 py-1 font-mono text-[11.5px]" title={path}>
                {path}
              </div>
            ))}
          </div>
        </div>
      </div>
    </aside>
  )
}
