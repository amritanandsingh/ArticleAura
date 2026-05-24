import {
  STATUS_OPTIONS,
  FREQUENCY_VALUES,
  MAX_WORKFLOWS,
  MAX_PROMPT_STEPS,
  MIN_PROMPT_STEPS,
  MAX_NAME_LEN,
  MIN_NAME_LEN,
  MAX_SUMMARY_LEN,
  MAX_CATEGORY_LEN,
  MAX_STEP_LEN,
  MIN_STEP_LEN,
} from './workflowConstants';

function trimmedLength(value) {
  return typeof value === 'string' ? value.trim().length : 0;
}

export function validateName(name) {
  const len = trimmedLength(name);
  if (len < MIN_NAME_LEN) return 'Name is required.';
  if (len > MAX_NAME_LEN) return `Name must be ${MAX_NAME_LEN} characters or fewer.`;
  return null;
}

export function validateSummary(summary) {
  if (summary == null || summary === '') return null;
  if (typeof summary !== 'string') return 'Summary must be text.';
  if (summary.length > MAX_SUMMARY_LEN) {
    return `Summary must be ${MAX_SUMMARY_LEN} characters or fewer.`;
  }
  return null;
}

export function validateStatus(status) {
  if (!STATUS_OPTIONS.includes(status)) return 'Select a status.';
  return null;
}

export function validateFrequency(frequency) {
  if (!FREQUENCY_VALUES.includes(frequency)) return 'Select a frequency.';
  return null;
}

export function validateCategory(category) {
  if (category == null || category === '') return null;
  if (typeof category !== 'string') return 'Category must be text.';
  if (category.length > MAX_CATEGORY_LEN) {
    return `Category must be ${MAX_CATEGORY_LEN} characters or fewer.`;
  }
  return null;
}

export function validatePromptStep(step) {
  const len = trimmedLength(step);
  if (len < MIN_STEP_LEN) return 'Step cannot be empty.';
  if (len > MAX_STEP_LEN) return `Step must be ${MAX_STEP_LEN} characters or fewer.`;
  return null;
}

export function validatePromptSteps(steps) {
  if (!Array.isArray(steps) || steps.length < MIN_PROMPT_STEPS) {
    return { _list: 'Add at least one prompt step.' };
  }
  if (steps.length > MAX_PROMPT_STEPS) {
    return { _list: `A workflow can have at most ${MAX_PROMPT_STEPS} steps.` };
  }

  const itemErrors = steps.map(validatePromptStep);
  const hasItemError = itemErrors.some(Boolean);
  if (hasItemError) {
    return { items: itemErrors };
  }
  return null;
}

export function validateWorkflow(draft) {
  const errors = {};

  const nameErr = validateName(draft.name);
  if (nameErr) errors.name = nameErr;

  const summaryErr = validateSummary(draft.summary);
  if (summaryErr) errors.summary = summaryErr;

  const statusErr = validateStatus(draft.status);
  if (statusErr) errors.status = statusErr;

  const frequencyErr = validateFrequency(draft.frequency);
  if (frequencyErr) errors.frequency = frequencyErr;

  const categoryErr = validateCategory(draft.category);
  if (categoryErr) errors.category = categoryErr;

  const stepsErr = validatePromptSteps(draft.promptSteps);
  if (stepsErr) errors.promptSteps = stepsErr;

  return Object.keys(errors).length ? errors : null;
}

export function validateCollection(drafts) {
  if (!Array.isArray(drafts)) return { _collection: 'Workflows must be a list.' };
  if (drafts.length > MAX_WORKFLOWS) {
    return { _collection: `You can have at most ${MAX_WORKFLOWS} workflows.` };
  }

  const seenIds = new Set();
  for (const draft of drafts) {
    if (!draft.workflowId) continue;
    if (seenIds.has(draft.workflowId)) {
      return { _collection: 'Duplicate workflow detected. Reload and try again.' };
    }
    seenIds.add(draft.workflowId);
  }

  return null;
}

export function hasAnyErrors(errors) {
  if (!errors) return false;
  return Object.keys(errors).some((key) => errors[key] != null);
}
