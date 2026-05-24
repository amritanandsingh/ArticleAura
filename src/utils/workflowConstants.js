export const STATUS_OPTIONS = ['ACTIVE', 'INACTIVE'];

export const STATUS_LABELS = {
  ACTIVE: 'Active',
  INACTIVE: 'Inactive',
};

export const FREQUENCY_LABELS = {
  ONCE: 'One time',
  HOURLY: 'Hourly',
  DAILY: 'Daily',
  WEEKLY: 'Weekly',
  MONTHLY: 'Monthly',
  CUSTOM: 'Custom',
};

export const FREQUENCY_VALUES = Object.keys(FREQUENCY_LABELS);

export const DEFAULT_STATUS = 'INACTIVE';
export const DEFAULT_FREQUENCY = 'DAILY';

export const MAX_WORKFLOWS = 100;
export const MAX_PROMPT_STEPS = 20;
export const MIN_PROMPT_STEPS = 1;
export const MAX_NAME_LEN = 120;
export const MIN_NAME_LEN = 1;
export const MAX_SUMMARY_LEN = 500;
export const MAX_CATEGORY_LEN = 60;
export const MAX_STEP_LEN = 1000;
export const MIN_STEP_LEN = 1;
