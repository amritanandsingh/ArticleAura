import React from 'react';
import {
  MAX_PROMPT_STEPS,
  MAX_STEP_LEN,
} from '../../utils/workflowConstants';

const PromptStepsEditor = ({ steps, errors, onChange, disabled }) => {
  const itemErrors = errors?.items || [];
  const listError = errors?._list;

  const updateStep = (index, value) => {
    const next = steps.slice();
    next[index] = value;
    onChange(next);
  };

  const removeStep = (index) => {
    const next = steps.filter((_, i) => i !== index);
    onChange(next);
  };

  const addStep = () => {
    if (steps.length >= MAX_PROMPT_STEPS) return;
    onChange([...steps, '']);
  };

  const moveStep = (index, direction) => {
    const target = index + direction;
    if (target < 0 || target >= steps.length) return;
    const next = steps.slice();
    [next[index], next[target]] = [next[target], next[index]];
    onChange(next);
  };

  return (
    <div className="wf-steps">
      <div className="wf-steps__header">
        <label className="wf-steps__label">
          Prompt Steps <span className="wf-steps__required">*</span>
        </label>
        <span className="wf-steps__count">
          {steps.length} / {MAX_PROMPT_STEPS}
        </span>
      </div>

      {listError && <div className="wf-steps__list-error">{listError}</div>}

      <ol className="wf-steps__list">
        {steps.map((step, index) => {
          const stepError = itemErrors[index];
          return (
            <li key={index} className="wf-steps__item">
              <span className="wf-steps__index">{index + 1}</span>
              <div className="wf-steps__field">
                <textarea
                  className={`wf-textarea wf-steps__textarea${stepError ? ' wf-textarea--error' : ''}`}
                  value={step}
                  onChange={(e) => updateStep(index, e.target.value)}
                  placeholder={`Describe step ${index + 1}…`}
                  maxLength={MAX_STEP_LEN}
                  rows={2}
                  disabled={disabled}
                  aria-invalid={Boolean(stepError)}
                />
                <div className="wf-steps__field-meta">
                  {stepError ? (
                    <span className="wf-steps__field-error">{stepError}</span>
                  ) : (
                    <span className="wf-steps__field-counter">
                      {step.length} / {MAX_STEP_LEN}
                    </span>
                  )}
                </div>
              </div>
              <div className="wf-steps__item-actions">
                <button
                  type="button"
                  className="wf-icon-btn"
                  onClick={() => moveStep(index, -1)}
                  disabled={disabled || index === 0}
                  aria-label="Move step up"
                  title="Move up"
                >
                  <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round">
                    <polyline points="18 15 12 9 6 15" />
                  </svg>
                </button>
                <button
                  type="button"
                  className="wf-icon-btn"
                  onClick={() => moveStep(index, 1)}
                  disabled={disabled || index === steps.length - 1}
                  aria-label="Move step down"
                  title="Move down"
                >
                  <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round">
                    <polyline points="6 9 12 15 18 9" />
                  </svg>
                </button>
                <button
                  type="button"
                  className="wf-icon-btn wf-icon-btn--danger"
                  onClick={() => removeStep(index)}
                  disabled={disabled || steps.length <= 1}
                  aria-label="Remove step"
                  title={steps.length <= 1 ? 'At least one step is required' : 'Remove step'}
                >
                  <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round">
                    <line x1="18" y1="6" x2="6" y2="18" />
                    <line x1="6" y1="6" x2="18" y2="18" />
                  </svg>
                </button>
              </div>
            </li>
          );
        })}
      </ol>

      <button
        type="button"
        className="wf-steps__add"
        onClick={addStep}
        disabled={disabled || steps.length >= MAX_PROMPT_STEPS}
      >
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
          <line x1="12" y1="5" x2="12" y2="19" />
          <line x1="5" y1="12" x2="19" y2="12" />
        </svg>
        Add step
      </button>
    </div>
  );
};

export default PromptStepsEditor;
