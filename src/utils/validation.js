// Validation rules
export const required = (message = 'This field is required') => (value) => {
  if (!value || (typeof value === 'string' && value.trim() === '')) {
    return message;
  }
  return '';
};

export const email = (message = 'Please enter a valid email address') => (value) => {
  if (!value) return '';
  
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(value)) {
    return message;
  }
  return '';
};

export const minLength = (min, message) => (value) => {
  if (!value) return '';
  
  if (value.length < min) {
    return message || `Must be at least ${min} characters`;
  }
  return '';
};

export const maxLength = (max, message) => (value) => {
  if (!value) return '';
  
  if (value.length > max) {
    return message || `Must be less than ${max} characters`;
  }
  return '';
};

export const pattern = (regex, message = 'Invalid format') => (value) => {
  if (!value) return '';
  
  if (!regex.test(value)) {
    return message;
  }
  return '';
};

export const passwordStrength = (message = 'Password must contain at least 8 characters, one uppercase, one lowercase, and one number') => (value) => {
  if (!value) return '';
  
  const strongPasswordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)[a-zA-Z\d@$!%*?&]{8,}$/;
  if (!strongPasswordRegex.test(value)) {
    return message;
  }
  return '';
};

export const confirmPassword = (passwordField = 'password', message = 'Passwords do not match') => (value, allValues) => {
  if (!value) return '';
  
  if (value !== allValues[passwordField]) {
    return message;
  }
  return '';
};

export const phoneNumber = (message = 'Please enter a valid phone number') => (value) => {
  if (!value) return '';
  
  const phoneRegex = /^[\+]?[1-9][\d]{0,15}$/;
  if (!phoneRegex.test(value.replace(/[\s\-\(\)]/g, ''))) {
    return message;
  }
  return '';
};

// Common validation rule sets
export const loginValidation = {
  email: [required('Email is required'), email()],
  password: [required('Password is required'), minLength(6, 'Password must be at least 6 characters')],
};

export const signupValidation = {
  firstName: [required('First name is required'), maxLength(50, 'First name must be less than 50 characters')],
  lastName: [required('Last name is required'), maxLength(50, 'Last name must be less than 50 characters')],
  email: [required('Email is required'), email()],
  password: [required('Password is required'), passwordStrength()],
  confirmPassword: [required('Please confirm your password'), confirmPassword()],
};

export const forgotPasswordValidation = {
  email: [required('Email is required'), email()],
};