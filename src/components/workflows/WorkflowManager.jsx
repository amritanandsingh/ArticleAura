import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import Button from '../Button';
import ConfirmDialog from '../ConfirmDialog';
import WorkflowCard from './WorkflowCard';
import { useAuth } from '../../context/AuthContext';
import { useToast } from '../../context/ToastContext';
import { getSession } from '../../services/cognitoService';
import { getWorkflows, saveWorkflows } from '../../services/workflowService';
import {
  DEFAULT_FREQUENCY,
  DEFAULT_STATUS,
  MAX_WORKFLOWS,
} from '../../utils/workflowConstants';
import {
  hasAnyErrors,
  validateCollection,
  validateWorkflow,
} from '../../utils/workflowValidation';
import './WorkflowManager.css';

function makeClientId() {
  if (typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function') {
    return crypto.randomUUID();
  }
  return `cid-${Date.now()}-${Math.random().toString(36).slice(2, 11)}`;
}

function baselineToDraft(workflow, clientId = makeClientId()) {
  return {
    clientId,
    workflowId: workflow.workflowId,
    name: workflow.name ?? '',
    summary: workflow.summary ?? '',
    status: workflow.status ?? DEFAULT_STATUS,
    frequency: workflow.frequency ?? DEFAULT_FREQUENCY,
    category: workflow.category ?? '',
    promptSteps: Array.isArray(workflow.promptSteps)
      ? workflow.promptSteps.slice()
      : [],
    createdAt: workflow.createdAt ?? null,
    updatedAt: workflow.updatedAt ?? null,
    _originalStatus: workflow.status ?? DEFAULT_STATUS,
  };
}

function makeBlankDraft() {
  return {
    clientId: makeClientId(),
    workflowId: undefined,
    name: '',
    summary: '',
    status: DEFAULT_STATUS,
    frequency: DEFAULT_FREQUENCY,
    category: '',
    promptSteps: [''],
    createdAt: null,
    updatedAt: null,
    _originalStatus: null,
  };
}

function normalizeForCompare(value) {
  return {
    name: (value.name ?? '').trim(),
    summary: (value.summary ?? '').trim(),
    status: value.status === 'DRAFT' ? 'INACTIVE' : value.status,
    frequency: value.frequency,
    category: (value.category ?? '').trim(),
    promptSteps: (value.promptSteps ?? [])
      .map((step) => (step ?? '').trim())
      .filter((step) => step.length > 0),
  };
}

function isDraftDirty(draft, baselineByWorkflowId) {
  if (!draft.workflowId) return true;
  const original = baselineByWorkflowId.get(draft.workflowId);
  if (!original) return true;
  return (
    JSON.stringify(normalizeForCompare(draft)) !==
    JSON.stringify(normalizeForCompare(original))
  );
}

function serializeForPut(draft) {
  const payload = {
    name: (draft.name ?? '').trim(),
    summary: (draft.summary ?? '').trim(),
    status: draft.status === 'DRAFT' ? 'INACTIVE' : draft.status,
    frequency: draft.frequency,
    category: (draft.category ?? '').trim(),
    promptSteps: (draft.promptSteps ?? [])
      .map((step) => (step ?? '').trim())
      .filter((step) => step.length > 0),
  };
  if (draft.workflowId) {
    payload.workflowId = draft.workflowId;
  }
  return payload;
}

const WorkflowManager = ({ email }) => {
  const navigate = useNavigate();
  const { logout } = useAuth();
  const { showToast } = useToast();

  const [baseline, setBaseline] = useState([]);
  const [drafts, setDrafts] = useState([]);
  const [errors, setErrors] = useState({});
  const [expandedId, setExpandedId] = useState(null);
  const [loadStatus, setLoadStatus] = useState('idle');
  const [loadError, setLoadError] = useState(null);
  const [saveStatus, setSaveStatus] = useState('idle');
  const [meta, setMeta] = useState(null);
  const [confirm, setConfirm] = useState(null);

  const cardRefs = useRef({});

  const baselineByWorkflowId = useMemo(() => {
    const map = new Map();
    baseline.forEach((w) => {
      if (w.workflowId) map.set(w.workflowId, w);
    });
    return map;
  }, [baseline]);

  const dirtyByClientId = useMemo(() => {
    const result = {};
    drafts.forEach((draft) => {
      result[draft.clientId] = isDraftDirty(draft, baselineByWorkflowId);
    });
    return result;
  }, [drafts, baselineByWorkflowId]);

  const deletedCount = useMemo(() => {
    const draftIds = new Set(drafts.map((d) => d.workflowId).filter(Boolean));
    let count = 0;
    baseline.forEach((b) => {
      if (b.workflowId && !draftIds.has(b.workflowId)) count += 1;
    });
    return count;
  }, [drafts, baseline]);

  const unsavedCount = useMemo(() => {
    const dirtyCardCount = Object.values(dirtyByClientId).filter(Boolean).length;
    return dirtyCardCount + deletedCount;
  }, [dirtyByClientId, deletedCount]);

  const hasUnsavedChanges = unsavedCount > 0;

  const fetchToken = useCallback(async () => {
    const { session } = await getSession();
    return session?.getIdToken()?.getJwtToken();
  }, []);

  const loadWorkflows = useCallback(
    async ({ silent = false } = {}) => {
      if (!email) return;
      if (!silent) setLoadStatus('loading');
      setLoadError(null);
      try {
        const token = await fetchToken();
        const { workflows, meta: nextMeta } = await getWorkflows(email, token);
        setBaseline(workflows);
        setDrafts(workflows.map((w) => baselineToDraft(w)));
        setMeta(nextMeta);
        setErrors({});
        setExpandedId(null);
        setLoadStatus('idle');
      } catch (err) {
        if (err?.code === 'INVALID_TOKEN' || err?.status === 401) {
          showToast('Your session has expired. Please sign in again.', 'error');
          logout();
          navigate('/');
          return;
        }
        setLoadStatus('error');
        setLoadError(err?.message || 'Unable to load workflows.');
      }
    },
    [email, fetchToken, logout, navigate, showToast],
  );

  useEffect(() => {
    loadWorkflows();
  }, [loadWorkflows]);

  useEffect(() => {
    if (!hasUnsavedChanges) return undefined;
    const handler = (event) => {
      event.preventDefault();
      event.returnValue = '';
      return '';
    };
    window.addEventListener('beforeunload', handler);
    return () => window.removeEventListener('beforeunload', handler);
  }, [hasUnsavedChanges]);

  useEffect(() => {
    const handler = () => {
      if (document.visibilityState !== 'visible') return;
      if (hasUnsavedChanges) return;
      loadWorkflows({ silent: true });
    };
    document.addEventListener('visibilitychange', handler);
    return () => document.removeEventListener('visibilitychange', handler);
  }, [hasUnsavedChanges, loadWorkflows]);

  const scrollCardIntoView = useCallback((clientId) => {
    const node = cardRefs.current[clientId];
    if (node && typeof node.scrollIntoView === 'function') {
      node.scrollIntoView({ behavior: 'smooth', block: 'center' });
    }
  }, []);

  const updateDraft = (next) => {
    setDrafts((prev) =>
      prev.map((d) => (d.clientId === next.clientId ? next : d)),
    );
    setErrors((prev) => {
      if (!prev[next.clientId]) return prev;
      const copy = { ...prev };
      delete copy[next.clientId];
      return copy;
    });
  };

  const toggleExpand = (clientId) => {
    setExpandedId((prev) => (prev === clientId ? null : clientId));
  };

  const handleAddWorkflow = () => {
    if (drafts.length >= MAX_WORKFLOWS) {
      showToast(`You can have at most ${MAX_WORKFLOWS} workflows.`, 'error');
      return;
    }
    const blank = makeBlankDraft();
    setDrafts((prev) => [blank, ...prev]);
    setExpandedId(blank.clientId);
    setTimeout(() => scrollCardIntoView(blank.clientId), 50);
  };

  const removeDraftLocally = (clientId) => {
    setDrafts((prev) => prev.filter((d) => d.clientId !== clientId));
    setErrors((prev) => {
      if (!prev[clientId]) return prev;
      const copy = { ...prev };
      delete copy[clientId];
      return copy;
    });
    setExpandedId((prev) => (prev === clientId ? null : prev));
  };

  const handleRequestDelete = (draft) => {
    if (!draft.workflowId) {
      removeDraftLocally(draft.clientId);
      return;
    }
    setConfirm({ kind: 'delete', clientId: draft.clientId, name: draft.name?.trim() || 'this workflow' });
  };

  const handleConfirmDelete = () => {
    if (!confirm || confirm.kind !== 'delete') return;
    removeDraftLocally(confirm.clientId);
    setConfirm(null);
    showToast('Workflow will be deleted when you save changes.', 'info');
  };

  const handleRevertCard = (draft) => {
    if (!draft.workflowId) {
      removeDraftLocally(draft.clientId);
      return;
    }
    const original = baselineByWorkflowId.get(draft.workflowId);
    if (!original) return;
    setDrafts((prev) =>
      prev.map((d) =>
        d.clientId === draft.clientId
          ? baselineToDraft(original, draft.clientId)
          : d,
      ),
    );
    setErrors((prev) => {
      if (!prev[draft.clientId]) return prev;
      const copy = { ...prev };
      delete copy[draft.clientId];
      return copy;
    });
  };

  const handleRequestDiscardAll = () => {
    if (!hasUnsavedChanges) return;
    setConfirm({ kind: 'discardAll' });
  };

  const handleConfirmDiscardAll = () => {
    setDrafts(baseline.map((w) => baselineToDraft(w)));
    setErrors({});
    setExpandedId(null);
    setConfirm(null);
    showToast('Unsaved changes discarded.', 'info');
  };

  const validateAll = () => {
    const nextErrors = {};
    drafts.forEach((draft) => {
      const fieldErrors = validateWorkflow(draft);
      if (fieldErrors) nextErrors[draft.clientId] = fieldErrors;
    });
    const collectionError = validateCollection(drafts);
    if (collectionError) {
      showToast(collectionError._collection, 'error');
    }
    setErrors(nextErrors);
    const firstInvalid = drafts.find((d) => nextErrors[d.clientId]);
    return { nextErrors, firstInvalid, collectionError };
  };

  const handleSave = async () => {
    if (!email) return;

    const { nextErrors, firstInvalid, collectionError } = validateAll();
    if (firstInvalid || collectionError) {
      if (firstInvalid) {
        setExpandedId(firstInvalid.clientId);
        setTimeout(() => scrollCardIntoView(firstInvalid.clientId), 50);
        showToast('Please fix the highlighted fields before saving.', 'error');
      }
      return;
    }

    if (!hasAnyErrors(nextErrors)) {
      setErrors({});
    }

    setSaveStatus('saving');
    try {
      const token = await fetchToken();
      const payload = drafts.map(serializeForPut);
      const { workflows, meta: nextMeta } = await saveWorkflows(email, token, payload);
      setBaseline(workflows);

      const previousExpandedWorkflowId = drafts.find((d) => d.clientId === expandedId)?.workflowId;
      const nextDrafts = workflows.map((w) => baselineToDraft(w));
      setDrafts(nextDrafts);

      if (previousExpandedWorkflowId) {
        const stillThere = nextDrafts.find((d) => d.workflowId === previousExpandedWorkflowId);
        setExpandedId(stillThere ? stillThere.clientId : null);
      } else {
        setExpandedId(null);
      }

      setMeta(nextMeta);
      setSaveStatus('idle');
      showToast('Workflows saved.', 'success');
    } catch (err) {
      setSaveStatus('error');

      if (err?.code === 'INVALID_TOKEN' || err?.status === 401) {
        showToast('Your session has expired. Please sign in again.', 'error');
        logout();
        navigate('/');
        return;
      }

      if (err?.code === 'UNKNOWN_WORKFLOW_ID') {
        showToast('Workflows changed elsewhere — reloading.', 'info');
        await loadWorkflows({ silent: true });
        return;
      }

      showToast(err?.message || 'Save failed. Re-syncing from server…', 'error');
      try {
        await loadWorkflows({ silent: true });
      } catch {
        // already surfaced
      }
    }
  };

  const handleManualRefresh = async () => {
    if (hasUnsavedChanges) {
      setConfirm({ kind: 'refreshWithUnsaved' });
      return;
    }
    await loadWorkflows();
    showToast('Workflows refreshed.', 'info');
  };

  const handleConfirmRefresh = async () => {
    setConfirm(null);
    await loadWorkflows();
    showToast('Workflows refreshed.', 'info');
  };

  const setCardRef = (clientId) => (node) => {
    if (node) {
      cardRefs.current[clientId] = node;
    } else {
      delete cardRefs.current[clientId];
    }
  };

  const isInitialLoading = loadStatus === 'loading' && drafts.length === 0;
  const showEmptyState =
    loadStatus === 'idle' && drafts.length === 0 && !loadError;
  const showLoadError = loadStatus === 'error' && drafts.length === 0;
  const limitReached = drafts.length >= MAX_WORKFLOWS;

  return (
    <section className="wf-manager animate-slideIn" aria-label="Workflow manager">
      <div className="wf-manager__header">
        <div className="wf-manager__heading">
          <h2 className="wf-manager__title">My Workflows</h2>
          <p className="wf-manager__subtitle">
            {drafts.length > 0
              ? `${drafts.length} ${drafts.length === 1 ? 'workflow' : 'workflows'}`
              : 'Build and manage the workflows that power your account.'}
            {meta?.workflowCount != null && drafts.length > 0 && (
              <span className="wf-manager__limit">
                {' '}· {drafts.length}/{MAX_WORKFLOWS}
              </span>
            )}
          </p>
        </div>
        <div className="wf-manager__header-actions">
          <Button
            variant="outline"
            size="sm"
            onClick={handleManualRefresh}
            disabled={loadStatus === 'loading' || saveStatus === 'saving'}
          >
            Refresh
          </Button>
          <Button
            variant="primary"
            size="sm"
            onClick={handleAddWorkflow}
            disabled={limitReached || saveStatus === 'saving'}
          >
            + Add Workflow
          </Button>
        </div>
      </div>

      {limitReached && (
        <div className="wf-manager__notice wf-manager__notice--warning">
          You've reached the {MAX_WORKFLOWS}-workflow limit. Delete one to add another.
        </div>
      )}

      {isInitialLoading && (
        <div className="wf-manager__status">Loading workflows…</div>
      )}

      {showLoadError && (
        <div className="wf-manager__error">
          <p>{loadError}</p>
          <Button variant="outline" size="sm" onClick={() => loadWorkflows()}>
            Try again
          </Button>
        </div>
      )}

      {showEmptyState && (
        <div className="wf-manager__empty">
          <h3>No workflows yet</h3>
          <p>Create your first workflow to start automating your account.</p>
          <Button variant="primary" size="md" onClick={handleAddWorkflow}>
            + Add your first workflow
          </Button>
        </div>
      )}

      {drafts.length > 0 && (
        <div className="wf-manager__list">
          {drafts.map((draft) => {
            const isExpanded = expandedId === draft.clientId;
            return (
              <div key={draft.clientId} ref={setCardRef(draft.clientId)}>
                <WorkflowCard
                  draft={draft}
                  errors={errors[draft.clientId]}
                  expanded={isExpanded}
                  isDirty={dirtyByClientId[draft.clientId]}
                  isNew={!draft.workflowId}
                  saving={saveStatus === 'saving'}
                  onToggleExpand={() => toggleExpand(draft.clientId)}
                  onChange={updateDraft}
                  onSave={handleSave}
                  onCancel={() => handleRevertCard(draft)}
                  onDelete={() => handleRequestDelete(draft)}
                />
              </div>
            );
          })}
        </div>
      )}

      {hasUnsavedChanges && (
        <div className="wf-manager__save-bar" role="region" aria-label="Unsaved changes">
          <div className="wf-manager__save-bar-info">
            <span className="wf-manager__save-bar-dot" aria-hidden="true" />
            <span>
              <strong>{unsavedCount}</strong>{' '}
              {unsavedCount === 1 ? 'unsaved change' : 'unsaved changes'}
            </span>
          </div>
          <div className="wf-manager__save-bar-actions">
            <Button
              variant="ghost"
              size="sm"
              onClick={handleRequestDiscardAll}
              disabled={saveStatus === 'saving'}
            >
              Discard
            </Button>
            <Button
              variant="primary"
              size="sm"
              onClick={handleSave}
              loading={saveStatus === 'saving'}
              disabled={saveStatus === 'saving'}
            >
              Save all changes
            </Button>
          </div>
        </div>
      )}

      <ConfirmDialog
        open={confirm?.kind === 'delete'}
        title="Delete workflow?"
        message={`"${confirm?.name || 'This workflow'}" will be removed when you save your changes. This cannot be undone after saving.`}
        confirmLabel="Delete"
        cancelLabel="Cancel"
        variant="primary"
        onConfirm={handleConfirmDelete}
        onCancel={() => setConfirm(null)}
      />

      <ConfirmDialog
        open={confirm?.kind === 'discardAll'}
        title="Discard unsaved changes?"
        message={`You have ${unsavedCount} unsaved ${unsavedCount === 1 ? 'change' : 'changes'}. All edits, additions, and pending deletions will be reverted.`}
        confirmLabel="Discard"
        cancelLabel="Keep editing"
        variant="primary"
        onConfirm={handleConfirmDiscardAll}
        onCancel={() => setConfirm(null)}
      />

      <ConfirmDialog
        open={confirm?.kind === 'refreshWithUnsaved'}
        title="Refresh and lose changes?"
        message="Refreshing will discard your unsaved changes and reload workflows from the server."
        confirmLabel="Refresh"
        cancelLabel="Keep editing"
        variant="primary"
        onConfirm={handleConfirmRefresh}
        onCancel={() => setConfirm(null)}
      />
    </section>
  );
};

export default WorkflowManager;
