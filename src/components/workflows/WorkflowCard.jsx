import React, { useEffect, useRef } from 'react';
import Button from '../Button';
import Input from '../Input';
import PromptStepsEditor from './PromptStepsEditor';
import {
  STATUS_LABELS,
  FREQUENCY_LABELS,
  FREQUENCY_VALUES,
  MAX_NAME_LEN,
  MAX_SUMMARY_LEN,
  MAX_CATEGORY_LEN,
} from '../../utils/workflowConstants';

function formatTimestamp(value) {
  if (!value) return null;
  try {
    return new Date(value).toLocaleString();
  } catch {
    return null;
  }
}

function statusToToggle(status) {
  return status === 'ACTIVE' ? 'ACTIVE' : 'INACTIVE';
}

const WorkflowCard = ({
  draft,
  errors,
  expanded,
  isDirty,
  isNew,
  saving,
  onToggleExpand,
  onChange,
  onSave,
  onCancel,
  onDelete,
}) => {
  const cardRef = useRef(null);
  const nameInputRef = useRef(null);

  useEffect(() => {
    if (expanded && nameInputRef.current) {
      nameInputRef.current.focus();
    }
  }, [expanded]);

  const update = (field) => (event) => {
    const value = event?.target ? event.target.value : event;
    onChange({ ...draft, [field]: value });
  };

  const updateStatus = (next) => {
    onChange({ ...draft, status: next });
  };

  const updateSteps = (steps) => {
    onChange({ ...draft, promptSteps: steps });
  };

  const createdLabel = formatTimestamp(draft.createdAt);
  const updatedLabel = formatTimestamp(draft.updatedAt);
  const toggleValue = statusToToggle(draft.status);
  const isActive = toggleValue === 'ACTIVE';

  const summaryPreview = draft.summary?.trim() || (isNew ? 'New workflow — add a summary.' : 'No summary provided.');

  const cardClass = [
    'wf-card',
    expanded ? 'wf-card--expanded' : '',
    isDirty ? 'wf-card--dirty' : '',
    isNew ? 'wf-card--new' : '',
  ].filter(Boolean).join(' ');

  return (
    <article ref={cardRef} className={cardClass}>
      <header
        className="wf-card__header"
        role="button"
        tabIndex={0}
        aria-expanded={expanded}
        onClick={onToggleExpand}
        onKeyDown={(event) => {
          if (event.key === 'Enter' || event.key === ' ') {
            event.preventDefault();
            onToggleExpand();
          }
        }}
      >
        <div className="wf-card__header-main">
          <div className="wf-card__title-row">
            <h3 className="wf-card__title">{draft.name?.trim() || 'Untitled workflow'}</h3>
            <span className={`wf-card__status-pill wf-card__status-pill--${isActive ? 'active' : 'inactive'}`}>
              {isActive ? STATUS_LABELS.ACTIVE : STATUS_LABELS.INACTIVE}
            </span>
          </div>
          <p className="wf-card__summary">{summaryPreview}</p>
          <div className="wf-card__chips">
            <span className="wf-card__chip wf-card__chip--frequency">
              {FREQUENCY_LABELS[draft.frequency] || draft.frequency}
            </span>
            {draft.category && (
              <span className="wf-card__chip">{draft.category}</span>
            )}
            {Array.isArray(draft.promptSteps) && draft.promptSteps.length > 0 && (
              <span className="wf-card__chip">
                {draft.promptSteps.length} {draft.promptSteps.length === 1 ? 'step' : 'steps'}
              </span>
            )}
            {isDirty && (
              <span className="wf-card__chip wf-card__chip--dirty">
                {isNew ? 'Unsaved' : 'Modified'}
              </span>
            )}
          </div>
        </div>
        <div className="wf-card__header-action" aria-hidden="true">
          <svg
            className={`wf-card__chevron${expanded ? ' wf-card__chevron--open' : ''}`}
            width="20"
            height="20"
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            strokeWidth="2.2"
            strokeLinecap="round"
            strokeLinejoin="round"
          >
            <polyline points="6 9 12 15 18 9" />
          </svg>
        </div>
      </header>

      {expanded && (
        <div className="wf-card__body animate-scaleIn">
          <div className="wf-card__field-grid">
            <div className="wf-card__field wf-card__field--full">
              <Input
                ref={nameInputRef}
                label="Name"
                required
                placeholder="e.g. Weekly digest"
                value={draft.name}
                onChange={update('name')}
                error={errors?.name}
                maxLength={MAX_NAME_LEN}
                disabled={saving}
              />
            </div>

            <div className="wf-card__field wf-card__field--full">
              <label className="wf-card__label">
                Summary
                <span className="wf-card__counter">
                  {(draft.summary || '').length} / {MAX_SUMMARY_LEN}
                </span>
              </label>
              <textarea
                className={`wf-textarea${errors?.summary ? ' wf-textarea--error' : ''}`}
                value={draft.summary || ''}
                onChange={update('summary')}
                placeholder="Briefly describe what this workflow does."
                maxLength={MAX_SUMMARY_LEN}
                rows={3}
                disabled={saving}
                aria-invalid={Boolean(errors?.summary)}
              />
              {errors?.summary && <div className="wf-card__field-error">{errors.summary}</div>}
            </div>

            <div className="wf-card__field">
              <label className="wf-card__label">Status</label>
              <div className="wf-segmented" role="radiogroup" aria-label="Status">
                <button
                  type="button"
                  role="radio"
                  aria-checked={isActive}
                  className={`wf-segmented__option${isActive ? ' wf-segmented__option--selected' : ''}`}
                  onClick={() => updateStatus('ACTIVE')}
                  disabled={saving}
                >
                  Active
                </button>
                <button
                  type="button"
                  role="radio"
                  aria-checked={!isActive}
                  className={`wf-segmented__option${!isActive ? ' wf-segmented__option--selected' : ''}`}
                  onClick={() => updateStatus('INACTIVE')}
                  disabled={saving}
                >
                  Inactive
                </button>
              </div>
              {errors?.status && <div className="wf-card__field-error">{errors.status}</div>}
            </div>

            <div className="wf-card__field">
              <label className="wf-card__label" htmlFor={`frequency-${draft.clientId}`}>
                Frequency
              </label>
              <div className="wf-select-wrap">
                <select
                  id={`frequency-${draft.clientId}`}
                  className={`wf-select${errors?.frequency ? ' wf-select--error' : ''}`}
                  value={draft.frequency}
                  onChange={update('frequency')}
                  disabled={saving}
                >
                  {FREQUENCY_VALUES.map((value) => (
                    <option key={value} value={value}>
                      {FREQUENCY_LABELS[value]}
                    </option>
                  ))}
                </select>
                <svg className="wf-select__chevron" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round">
                  <polyline points="6 9 12 15 18 9" />
                </svg>
              </div>
              {errors?.frequency && <div className="wf-card__field-error">{errors.frequency}</div>}
            </div>

            <div className="wf-card__field wf-card__field--full">
              <Input
                label="Category"
                placeholder="e.g. news, marketing"
                value={draft.category || ''}
                onChange={update('category')}
                error={errors?.category}
                maxLength={MAX_CATEGORY_LEN}
                disabled={saving}
                helperText={!errors?.category ? 'Optional — helps you group related workflows.' : undefined}
              />
            </div>

            <div className="wf-card__field wf-card__field--full">
              <PromptStepsEditor
                steps={Array.isArray(draft.promptSteps) ? draft.promptSteps : []}
                errors={errors?.promptSteps}
                onChange={updateSteps}
                disabled={saving}
              />
            </div>
          </div>

          <div className="wf-card__footer">
            <div className="wf-card__timestamps">
              {isNew ? (
                <span className="wf-card__timestamp">Not saved yet</span>
              ) : (
                <>
                  {createdLabel && (
                    <span className="wf-card__timestamp">
                      <strong>Created</strong> {createdLabel}
                    </span>
                  )}
                  {updatedLabel && (
                    <span className="wf-card__timestamp">
                      <strong>Updated</strong> {updatedLabel}
                    </span>
                  )}
                </>
              )}
            </div>

            <div className="wf-card__actions">
              <Button
                variant="ghost"
                size="sm"
                onClick={onDelete}
                disabled={saving}
              >
                {isNew ? 'Remove' : 'Delete'}
              </Button>
              <Button
                variant="outline"
                size="sm"
                onClick={onCancel}
                disabled={saving || (!isDirty && !isNew)}
              >
                {isNew ? 'Discard' : 'Revert'}
              </Button>
              <Button
                variant="primary"
                size="sm"
                onClick={onSave}
                loading={saving}
                disabled={saving}
              >
                Save
              </Button>
            </div>
          </div>
        </div>
      )}
    </article>
  );
};

export default WorkflowCard;
