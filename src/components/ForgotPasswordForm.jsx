import React from 'react';
import Button from './Button';
import Input from './Input';
import useForm from '../hooks/useForm';
import { forgotPasswordValidation } from '../utils/validation';
import './AuthForms.css';

const ForgotPasswordForm = ({ onSubmit, onBack, loading = false }) => {
  const { values, errors, touched, handleChange, handleBlur, handleSubmit } = useForm(
    { email: '' },
    forgotPasswordValidation
  );

  const onFormSubmit = async (formValues) => {
    if (onSubmit) await onSubmit(formValues.email);
  };

  return (
    <form
      className="auth-form"
      onSubmit={(e) => { e.preventDefault(); handleSubmit(onFormSubmit); }}
      noValidate
    >
      <div className="verify-form__info">
        <div className="verify-form__icon">
          <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
            <rect x="3" y="11" width="18" height="11" rx="2" ry="2"/>
            <path d="M7 11V7a5 5 0 0 1 10 0v4"/>
          </svg>
        </div>
        <p className="verify-form__message">
          Enter your account email and we'll send you a reset code.
        </p>
      </div>

      <div className="auth-form__fields">
        <Input
          name="email"
          type="email"
          label="Email Address"
          placeholder="Enter your email"
          value={values.email}
          onChange={handleChange}
          onBlur={handleBlur}
          error={touched.email ? errors.email : ''}
          required
          disabled={loading}
          icon={
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z"/>
              <polyline points="22,6 12,13 2,6"/>
            </svg>
          }
        />
      </div>

      <Button
        type="submit"
        variant="primary"
        size="lg"
        fullWidth
        loading={loading}
        disabled={loading}
        className="auth-form__submit"
      >
        Send Reset Code
      </Button>

      <button type="button" className="auth-form__link" onClick={onBack} disabled={loading}>
        ← Back to Sign In
      </button>
    </form>
  );
};

export default ForgotPasswordForm;
